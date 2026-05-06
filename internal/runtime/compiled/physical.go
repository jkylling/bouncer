package compiled

import (
	"context"

	pb "github.com/jkylling/bouncer/internal/pb"
)

// PhysicalAPI performs the upstream HTTP call that a meta `request`
// expression evaluates to. The runtime is deliberately sync; concurrency
// is the caller's concern.
//
// The ctx argument is the inbound request's context: cancelling the
// inbound HTTP request must abort any pending upstream side calls. Real
// implementations propagate ctx to net/http via NewRequestWithContext.
type PhysicalAPI interface {
	Call(ctx context.Context, req *pb.MetaRequest) (*pb.Response, error)
}

// PhysicalAPIResolver maps an API name (e.g. "google.drive") to the
// PhysicalAPI that should issue calls on its behalf. The runtime calls
// the resolver per Meta side call, not per request: a `gmail` policy
// that binds `google.drive.file{...}` resolves "google.drive" — not the
// routed-request API — so cross-API completers hit the right upstream.
//
// Production wiring caches the per-API client; tests typically supply a
// single mock keyed against any name (see runtime test helpers).
type PhysicalAPIResolver func(apiName string) (PhysicalAPI, error)
