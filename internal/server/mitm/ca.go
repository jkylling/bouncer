package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	DefaultMaxCacheSize = 1024
	DefaultExpiryMargin = 5 * time.Minute
)

// CA holds the intermediate cert + private key used to sign per-SNI
// leaves. Leaves are short-lived and cached LRU.
//
// Safe for concurrent use. Two CONNECTs to the same fresh host may
// both issue; the second Add overwrites the first and one redundant
// keypair is cheap.
type CA struct {
	cert    *x509.Certificate
	certDER []byte
	key     any // *rsa.PrivateKey or *ecdsa.PrivateKey

	LeafTTL      time.Duration
	ExpiryMargin time.Duration

	cache *lru.Cache[string, cacheEntry]
}

type cacheEntry struct {
	leaf     *tls.Certificate
	notAfter time.Time
}

func CAFromFiles(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("mitm: read ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("mitm: read ca key: %w", err)
	}
	return CAFromPEM(certPEM, keyPEM)
}

func CAFromPEM(certPEM, keyPEM []byte) (*CA, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("mitm: ca cert PEM missing or not CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse ca cert: %w", err)
	}
	if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("mitm: ca cert lacks IsCA / KeyUsageCertSign")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("mitm: ca key PEM empty")
	}
	key, err := parsePrivateKey(keyBlock)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse ca key: %w", err)
	}

	cache, err := lru.New[string, cacheEntry](DefaultMaxCacheSize)
	if err != nil {
		return nil, fmt.Errorf("mitm: leaf cache: %w", err)
	}

	return &CA{
		cert:         cert,
		certDER:      cert.Raw,
		key:          key,
		LeafTTL:      24 * time.Hour,
		ExpiryMargin: DefaultExpiryMargin,
		cache:        cache,
	}, nil
}

// parsePrivateKey accepts the three PEM key shapes openssl emits:
// PKCS#8, RSA PKCS#1 legacy, and SEC1 ECDSA legacy.
func parsePrivateKey(block *pem.Block) (any, error) {
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
	}
}

// leafFor returns the cached leaf for host or issues a new one. Add
// on an existing key overwrites and refreshes LRU position, so a
// stale hit just falls through to issue.
func (ca *CA) leafFor(host string) (*tls.Certificate, error) {
	margin := ca.ExpiryMargin
	if margin <= 0 {
		margin = DefaultExpiryMargin
	}
	if e, ok := ca.cache.Get(host); ok && time.Now().Add(margin).Before(e.notAfter) {
		return e.leaf, nil
	}
	leaf, notAfter, err := ca.issueLeaf(host)
	if err != nil {
		return nil, err
	}
	ca.cache.Add(host, cacheEntry{leaf: leaf, notAfter: notAfter})
	return leaf, nil
}

// issueLeaf generates an ECDSA P-256 keypair, builds a leaf with the
// SNI in CN + SAN, and signs it with the CA. ECDSA is plenty for the
// trust path here and ~5x cheaper than RSA-2048 keygen.
func (ca *CA) issueLeaf(host string) (*tls.Certificate, time.Time, error) {
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("mitm: leaf keygen: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("mitm: leaf serial: %w", err)
	}
	now := time.Now()
	notAfter := now.Add(ca.LeafTTL)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-1 * time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// RFC 5280 §4.2.1.9 only SHOULDs cA=FALSE on a missing
		// BasicConstraints, so set it explicitly — a non-conformant
		// stack could otherwise let a leaf sign further certs.
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("mitm: leaf sign: %w", err)
	}
	// Re-parse for tls.Certificate.Leaf. Failure would be a crypto/x509
	// bug; nil is harmless because Leaf is an optimisation.
	parsed, _ := x509.ParseCertificate(der)
	return &tls.Certificate{
		Certificate: [][]byte{der, ca.certDER},
		PrivateKey:  leafKey,
		Leaf:        parsed,
	}, notAfter, nil
}

func randomSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, max)
}

// GenerateCA issues a self-signed RSA-2048 CA valid for the given
// duration. Used by `bouncer init --mitm` (10 years) and tests (24h).
// Empty commonName falls back to "bouncer MITM CA".
func GenerateCA(commonName string, validity time.Duration) (caCertPEM, caKeyPEM []byte, err error) {
	if commonName == "" {
		commonName = "bouncer MITM CA"
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(validity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	caCertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	caKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return caCertPEM, caKeyPEM, nil
}

// GenerateCAForTest is a test-only convenience over GenerateCA.
func GenerateCAForTest() (caCertPEM, caKeyPEM []byte, err error) {
	return GenerateCA("bouncer mitm test CA", 24*time.Hour)
}
