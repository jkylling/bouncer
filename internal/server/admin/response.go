package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// writeJSON writes v as a 200 application/json response. The
// majority of admin handlers want this shape, so a thin wrapper
// keeps callsites focused on the value rather than the status.
func writeJSON(w http.ResponseWriter, v any) {
	writeJSONStatus(w, http.StatusOK, "", v)
}

// htmlHandler returns an HTTP handler that serves body as
// text/html with no-store caching. Shared between the admin index
// and the apis viewer so a future header tweak lands in one place.
func htmlHandler(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	}
}

// writeJSONStatus writes v as JSON with the given status. Headers
// must be set before WriteHeader. location, when non-empty, sets the
// Location header (used by 201 Created bodies).
//
// Marshalling happens before WriteHeader so a marshal failure (cycle,
// NaN float, unsupported type) produces a 500 rather than a 200 with
// an empty body — the latter would silently lie to the client.
//
// Location is sanity-checked for embedded CR/LF — Go 1.20+ panics
// on those, so an unsanitized caller-derived value would convert
// the panic into a 500 here rather than crashing the handler.
func writeJSONStatus(w http.ResponseWriter, status int, location string, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		slog.Warn("admin: marshal response", "err", err)
		writeJSONError(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if location != "" {
		if strings.ContainsAny(location, "\r\n") {
			slog.Error("admin: location header contains CRLF, dropping",
				"location", location)
			writeJSONError(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Location", location)
	}
	w.WriteHeader(status)
	_, _ = w.Write(buf)
}

// errorBody is the JSON shape every admin error response carries.
// Mirrors the data-plane DenialResponse shape (minus next_steps) so
// a generic JSON consumer sees one schema across both surfaces.
type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// writeJSONError replaces http.Error throughout the admin package so
// every error reaches the client as JSON rather than text/plain. The
// argument order mirrors http.Error (message then status) so the
// callsite swap was a single sed.
func writeJSONError(w http.ResponseWriter, message string, status int) {
	body, _ := json.Marshal(errorBody{Error: http.StatusText(status), Message: message})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// Sentinels returned by decodeJSONBody; writeMappedError peels them
// to 413 and 400 so callers' tables don't have to.
var errBodyTooLarge = errors.New("body too large")

type decodeError struct{ cause error }

func (e *decodeError) Error() string { return "invalid JSON: " + e.cause.Error() }

func isDecodeError(err error) bool {
	var de *decodeError
	return errors.As(err, &de)
}

// errMap.msg, when empty, falls back to err.Error() at write time.
type errMap struct {
	sentinel error
	status   int
	msg      string
}

// writeMappedError is the shared error→status dispatcher. First match
// wins, so order entries with more-specific sentinels first when a
// single err satisfies multiple rows.
func writeMappedError(ctx context.Context, w http.ResponseWriter, where string, err error, table []errMap) {
	if errors.Is(err, errBodyTooLarge) {
		writeJSONError(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	if isDecodeError(err) {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, m := range table {
		if errors.Is(err, m.sentinel) {
			msg := m.msg
			if msg == "" {
				msg = err.Error()
			}
			writeJSONError(w, msg, m.status)
			return
		}
	}
	slog.ErrorContext(ctx, where, "err", err)
	writeJSONError(w, "server error", http.StatusInternalServerError)
}

// decodeJSONBody applies the body cap and rejects unknown fields.
// Empty body → nil so callers' validators (rather than a raw
// "invalid JSON: EOF") report the first missing required field.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, max int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, max)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errBodyTooLarge
		}
		return &decodeError{cause: err}
	}
	return nil
}
