// Package httpdo declares the one-method HTTP client interface that
// apiclient and the oauth handler both reduce to: a thing that
// can run an *http.Request and produce a response. *http.Client
// satisfies it; tests stub it. Pulled out of the two packages so
// the shared shape doesn't drift if one ever needs to grow extra
// methods.
package httpdo

import "net/http"

// Client is the subset of *http.Client both consumers use. Keep it
// at one method — anything bigger is a sign the boundary should
// move, not that the interface should grow.
type Client interface {
	Do(req *http.Request) (*http.Response, error)
}
