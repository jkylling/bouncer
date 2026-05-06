package observability

import "go.opentelemetry.io/otel/attribute"

// Span attribute keys. Centralised so the tracing taxonomy stays
// stable across the codebase.
const (
	attrAPIName        = "api.name"
	attrPolicyDecision = "policy.decision"
	attrSubject        = "proxy.subject"
)

// APIName / PolicyDecision / Subject build the attribute.KeyValue
// pairs span.SetAttributes wants. Keeps call sites short and the
// wire strings in one place.
func APIName(name string) attribute.KeyValue {
	return attribute.String(attrAPIName, name)
}

func PolicyDecision(d string) attribute.KeyValue {
	return attribute.String(attrPolicyDecision, d)
}

func Subject(subject string) attribute.KeyValue {
	return attribute.String(attrSubject, subject)
}
