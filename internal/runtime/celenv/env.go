package celenv

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/jkylling/bouncer/internal/pb"
)

// protoTypes returns the proto messages exposed across every CEL env we
// build (request/response envelope plus the http-helper output type).
// Single source of truth so the static (http-helper) registry and the
// per-env base registry never disagree.
func protoTypes() []protoreflect.ProtoMessage {
	return []protoreflect.ProtoMessage{
		&pb.Request{},
		&pb.Response{},
		&pb.MetaRequest{},
		&pb.KeyValue{},
		&pb.Principal{},
	}
}

// NewProtoRegistry returns a fresh *types.Registry seeded with the
// shared proto types. The cel-go API can return an error here, but it
// only does so when the inputs aren't valid proto messages — our inputs
// are static and known-good, so we treat any failure as a programmer
// bug and panic.
func NewProtoRegistry() *types.Registry {
	reg, err := types.NewRegistry(protoTypes()...)
	if err != nil {
		panic("celenv: proto registry: " + err.Error())
	}
	return reg
}

// staticRegistry caches a registry shared by the http helper bindings,
// which need a types.Adapter to convert their freshly-built proto
// messages back to ref.Val without access to the per-env adapter.
var (
	staticRegistryOnce sync.Once
	staticRegistryVal  types.Adapter
)

func staticRegistry() types.Adapter {
	staticRegistryOnce.Do(func() { staticRegistryVal = NewProtoRegistry() })
	return staticRegistryVal
}

// HTTPHelpers registers get/delete/post/put/patch CEL functions plus
// the form-encoded post_form variant. The bodyless verbs accept
// (string) and return MetaRequest{method, path}; the body-carrying
// verbs accept (string, dyn) and convert the body via celToPbValue
// into MetaRequest{method, path, body}. post_form additionally stamps
// content_type=application/x-www-form-urlencoded so apiclient
// serialises the body as form fields rather than JSON — needed for
// Slack-style endpoints that reject browser-session (xoxc) tokens
// carrying JSON.
//
// Only the request env exposes these — they're the canonical builders
// for a meta's request: expression, and have no use anywhere else.
func HTTPHelpers() cel.EnvOption {
	return cel.Lib(httpHelpersLib{})
}

type httpHelpersLib struct{}

// Compile-time interface assertion.
var _ cel.Library = httpHelpersLib{}

func (httpHelpersLib) LibraryName() string {
	return "bouncer.http"
}

func (httpHelpersLib) CompileOptions() []cel.EnvOption {
	mr := cel.ObjectType("bouncer.MetaRequest")
	bodyless := func(name, method string) cel.EnvOption {
		return cel.Function(name,
			cel.Overload(name+"_string", []*cel.Type{cel.StringType}, mr,
				cel.UnaryBinding(func(path ref.Val) ref.Val {
					return makeMetaRequest(method, path, nil, "")
				}),
			),
		)
	}
	withBody := func(name, method, contentType string) cel.EnvOption {
		return cel.Function(name,
			cel.Overload(name+"_string_dyn", []*cel.Type{cel.StringType, cel.DynType}, mr,
				cel.BinaryBinding(func(path, body ref.Val) ref.Val {
					return makeMetaRequest(method, path, body, contentType)
				}),
			),
		)
	}
	return []cel.EnvOption{
		bodyless("get", "GET"),
		bodyless("delete", "DELETE"),
		withBody("post", "POST", ""),
		withBody("put", "PUT", ""),
		withBody("patch", "PATCH", ""),
		withBody("post_form", "POST", "application/x-www-form-urlencoded"),
	}
}

func (httpHelpersLib) ProgramOptions() []cel.ProgramOption {
	return nil
}

func makeMetaRequest(method string, path ref.Val, body ref.Val, contentType string) ref.Val {
	pathStr, ok := path.(types.String)
	if !ok {
		return types.NewErr("http helper: path must be string, got %T", path)
	}
	rawPath := string(pathStr)
	if err := validateMetaPath(rawPath); err != nil {
		return types.NewErr("http helper: %v", err)
	}
	mr := &pb.MetaRequest{
		Method:      method,
		Path:        rawPath,
		ContentType: contentType,
	}
	if body != nil {
		v, err := celToPbValue(body)
		if err != nil {
			return types.NewErr("http helper body: %v", err)
		}
		mr.Body = v
	}
	return staticRegistry().NativeToValue(mr)
}

// validateMetaPath rejects path strings that would let a policy
// author drive the upstream call to a different resource than the
// policy gate evaluated. apiclient.JoinPath is byte-faithful by
// design (see its doc): it forwards `..` and `.` segments verbatim
// so the bytes upstream sees match what the policy compared. That
// promise is correct for inbound-request matching, where the path
// template was compiled at config time and matched byte-for-byte —
// but the path produced by `get('/users/' + input.id)` is built at
// CEL eval time from input that an attacker may control. RFC 3986
// §5.2.4 dot-segment removal then collapses `../../admin` into a
// resource the gate never saw.
//
// Reject any `.` or `..` segment up front. Operators who genuinely
// want a literal `..` in a URL component must percent-encode it
// (`%2E%2E`), which the URL machinery preserves and the upstream
// will not normalise back.
func validateMetaPath(p string) error {
	pathOnly := p
	if i := strings.IndexByte(pathOnly, '?'); i >= 0 {
		pathOnly = pathOnly[:i]
	}
	if i := strings.IndexByte(pathOnly, '#'); i >= 0 {
		pathOnly = pathOnly[:i]
	}
	for _, seg := range strings.Split(strings.TrimPrefix(pathOnly, "/"), "/") {
		if seg == ".." || seg == "." {
			return fmt.Errorf("path %q must not contain %q segment", p, seg)
		}
	}
	return nil
}
