package mitm

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"testing"
	"time"
)

func mustCA(t *testing.T) (*CA, []byte) {
	t.Helper()
	certPEM, keyPEM, err := GenerateCAForTest()
	if err != nil {
		t.Fatalf("GenerateCAForTest: %v", err)
	}
	ca, err := CAFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("CAFromPEM: %v", err)
	}
	return ca, certPEM
}

// TestLeafForReturnsCachedCert: two calls for the same host return the
// same *tls.Certificate — without the cache every TLS handshake would
// regenerate a key.
func TestLeafForReturnsCachedCert(t *testing.T) {
	ca, _ := mustCA(t)

	a, err := ca.leafFor("gmail.googleapis.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	b, err := ca.leafFor("gmail.googleapis.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	if a != b {
		t.Errorf("cache miss on second leafFor: a=%p b=%p", a, b)
	}
}

// TestLeafForDistinctHostsDistinctCerts: a different SNI must yield a
// different leaf, otherwise a real client would fail SAN verify.
func TestLeafForDistinctHostsDistinctCerts(t *testing.T) {
	ca, _ := mustCA(t)
	a, _ := ca.leafFor("gmail.googleapis.com")
	b, _ := ca.leafFor("oauth2.googleapis.com")
	if a == b {
		t.Fatal("two hosts shared the same cached leaf")
	}
	if a.Leaf.Subject.CommonName != "gmail.googleapis.com" {
		t.Errorf("leaf CN = %q, want gmail.googleapis.com", a.Leaf.Subject.CommonName)
	}
	if len(a.Leaf.DNSNames) != 1 || a.Leaf.DNSNames[0] != "gmail.googleapis.com" {
		t.Errorf("leaf DNSNames = %v, want [gmail.googleapis.com]", a.Leaf.DNSNames)
	}
}

// TestLeafForIPHostUsesIPSAN: when the SNI is a literal IP, the leaf
// must carry an IP SAN — DNS-only would fail under tls.Config when the
// client verifies an IP address.
func TestLeafForIPHostUsesIPSAN(t *testing.T) {
	ca, _ := mustCA(t)
	leaf, err := ca.leafFor("127.0.0.1")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	if len(leaf.Leaf.IPAddresses) != 1 || !leaf.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("leaf IPAddresses = %v, want [127.0.0.1]", leaf.Leaf.IPAddresses)
	}
	if len(leaf.Leaf.DNSNames) != 0 {
		t.Errorf("leaf DNSNames = %v, want empty for an IP SNI", leaf.Leaf.DNSNames)
	}
}

// TestLeafVerifiesAgainstCA: end-to-end verify with the CA in the trust
// pool. Catches chain-wiring regressions (e.g. forgetting the CA der on
// tls.Certificate.Certificate).
func TestLeafVerifiesAgainstCA(t *testing.T) {
	ca, certPEM := mustCA(t)
	leaf, err := ca.leafFor("example.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("AppendCertsFromPEM: false")
	}
	intermediates := x509.NewCertPool()
	for _, der := range leaf.Certificate[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse intermediate: %v", err)
		}
		intermediates.AddCert(c)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       "example.com",
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestLeafForReIssuesExpiredCachedCert: a cached leaf past ExpiryMargin
// must be dropped on next access, not served stale.
func TestLeafForReIssuesExpiredCachedCert(t *testing.T) {
	ca, _ := mustCA(t)
	// TTL well below the expiry margin so the first issue is "stale on
	// arrival" — the next access has to re-issue.
	ca.LeafTTL = time.Millisecond
	ca.ExpiryMargin = time.Hour

	a, err := ca.leafFor("gmail.googleapis.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	// Bump TTL so the second issue is genuinely fresh — otherwise the
	// assertions race the clock.
	ca.LeafTTL = time.Hour
	b, err := ca.leafFor("gmail.googleapis.com")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	if a == b {
		t.Errorf("expired leaf was returned from cache: a=%p b=%p", a, b)
	}
	if b.Leaf.NotAfter.Before(time.Now()) {
		t.Errorf("re-issued leaf NotAfter %v is already in the past", b.Leaf.NotAfter)
	}
}

// TestLeafForEvictsOldestPastCap: past the cap the oldest entry must
// be gone — without it a hostile client could grow this map unbounded.
func TestLeafForEvictsOldestPastCap(t *testing.T) {
	ca, _ := mustCA(t)
	ca.cache.Resize(3)

	a, _ := ca.leafFor("a.example")
	_, _ = ca.leafFor("b.example")
	_, _ = ca.leafFor("c.example")
	_, _ = ca.leafFor("d.example") // should evict "a"

	if got := ca.cache.Len(); got != 3 {
		t.Errorf("cache size = %d, want 3 after eviction", got)
	}
	if ca.cache.Contains("a.example") {
		t.Error("a.example survived eviction; oldest entry should be gone")
	}
	a2, _ := ca.leafFor("a.example") // re-issues
	if a == a2 {
		t.Errorf("re-requested host returned the evicted *tls.Certificate")
	}
}

// TestLeafForLRUTouchOnHit: a hit on an older entry moves it to the
// front. Without the touch the cache would behave as FIFO and a hot
// host could be evicted just because it was inserted first.
func TestLeafForLRUTouchOnHit(t *testing.T) {
	ca, _ := mustCA(t)
	ca.cache.Resize(3)

	hot, _ := ca.leafFor("hot.example") // entry 1
	_, _ = ca.leafFor("b.example")      // entry 2
	_, _ = ca.leafFor("c.example")      // entry 3
	hot2, _ := ca.leafFor("hot.example")
	if hot != hot2 {
		t.Fatal("hot.example refetched a different cert before any eviction")
	}
	_, _ = ca.leafFor("d.example")

	if !ca.cache.Contains("hot.example") {
		t.Error("hot.example was evicted; LRU touch did not survive insert")
	}
	if ca.cache.Contains("b.example") {
		t.Error("b.example survived; expected it to be evicted as the new oldest")
	}
}

// TestLeafForCacheStableUnderRepeatedPressure: the cap holds under more
// inserts than the cap allows. Catches an off-by-one in the eviction.
func TestLeafForCacheStableUnderRepeatedPressure(t *testing.T) {
	ca, _ := mustCA(t)
	ca.cache.Resize(8)
	for i := 0; i < 100; i++ {
		_, err := ca.leafFor(fmt.Sprintf("host-%d.example", i))
		if err != nil {
			t.Fatalf("leafFor: %v", err)
		}
	}
	if got := ca.cache.Len(); got != 8 {
		t.Errorf("cache size = %d, want 8 after pressure", got)
	}
}

// TestCAFromPEMRejectsNonCA: a leaf cert masquerading as a CA must fail
// at load time, not silently sign children that no client trusts.
func TestCAFromPEMRejectsNonCA(t *testing.T) {
	certPEM, keyPEM, err := GenerateCAForTest()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	ca, err := CAFromPEM(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("seed CA: %v", err)
	}
	leaf, err := ca.leafFor("not-a-ca.example")
	if err != nil {
		t.Fatalf("leafFor: %v", err)
	}
	if len(leaf.Certificate) == 0 {
		t.Fatal("no leaf bytes")
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]})
	if _, err := CAFromPEM(leafPEM, keyPEM); err == nil {
		t.Fatal("expected CAFromPEM to reject a non-CA cert")
	}
}
