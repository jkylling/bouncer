package admin

import (
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
)

// CAPath serves the public half of the MITM CA so an agent on the
// same host can fetch and trust it without an operator-mediated
// out-of-band copy. The CA private key never leaves the proxy; only
// the certificate is exposed.
//
// This is the bootstrap-trust corner of HTTPS_PROXY mode: the agent
// fetches `mitm-ca.crt`, drops it into its trust store (or points
// `SSL_CERT_FILE` / equivalent at it), and from then on the proxy's
// per-SNI leaf certs verify cleanly. Localhost-only deployments are
// the intended use — a LAN attacker who can answer for the proxy's
// host could swap the CA at fetch time, so do not expose this
// endpoint over an untrusted network.
const CAPath = "/_api/ca.crt"

// MountCA attaches GET CAPath, reading caPath at request time. caPath
// may be empty (MITM disabled) — the handler 404s in that case
// rather than panicking, so a deployment without MITM keeps the
// rest of `/_api/...` working.
//
// Open by design: the CA cert is the public half, and the agent
// fetches it before it has any credential to authenticate with.
func MountCA(r chi.Router, caPath string) {
	r.Get(CAPath, caHandler(caPath))
}

// caHandler reads the file on every request rather than at boot. The
// CA file rarely changes, but reading per-request keeps the handler
// honest when an operator regenerates it (e.g. `bouncer init --force`)
// without a process restart.
func caHandler(caPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if caPath == "" {
			writeJSONError(w, "MITM disabled — no CA configured", http.StatusNotFound)
			return
		}
		body, err := os.ReadFile(caPath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				writeJSONError(w, "CA cert not found", http.StatusNotFound)
				return
			}
			slog.ErrorContext(r.Context(), "ca: read", "path", caPath, "err", err)
			writeJSONError(w, "server error", http.StatusInternalServerError)
			return
		}
		// `application/x-pem-file` is the de-facto media type for
		// PEM-encoded keys/certs; curl/openssl/python all accept it
		// transparently. `application/x-x509-ca-cert` would trigger
		// browser cert-install dialogs, but the intended consumer
		// here is a CLI agent piping into a trust-store update.
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Disposition", `attachment; filename="bouncer-mitm-ca.crt"`)
		_, _ = w.Write(body)
	}
}
