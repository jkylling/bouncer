// Package services projects per-bundle service metadata (slug, title,
// OAuth dance config, bring-your-own-token variants, suggested
// policies) into the JSON shape the /_api/services surface returns.
//
// The package is a small read-only aggregator: it does no I/O on its
// own, taking the LoadedService snapshot from the bundles loader plus
// a connection-state lookup from the connections store. That keeps
// the HTTP handler logic-free and lets tests drive the aggregator
// with hand-rolled fixtures.
package services

import (
	"errors"
	"fmt"

	"github.com/jkylling/bouncer/internal/control/bundles"
	"github.com/jkylling/bouncer/internal/control/connections"
)

// Sentinel errors. The HTTP layer maps these onto statuses.
var (
	ErrUnknown = errors.New("unknown service")
)

// Descriptor is the JSON shape one service exposes on /_api/services.
// Slug is the canonical key; ConnectedVariant is empty when the
// service hasn't been configured yet. OAuthAvailable reports whether
// the runtime env has the client-id/secret pair the bundle declared,
// so the UI knows whether to grey out the Sign-in tab.
type Descriptor struct {
	Slug             string              `json:"slug"`
	Title            string              `json:"title"`
	Description      string              `json:"description,omitempty"`
	BundleName       string              `json:"bundle_name,omitempty"`
	APIs             []string            `json:"apis,omitempty"`
	OAuthAvailable   bool                `json:"oauth_available"`
	OAuthScopes      []string            `json:"oauth_scopes,omitempty"`
	TokenVariants    []VariantDescriptor `json:"token_variants,omitempty"`
	SuggestedPolicy  []PolicyDescriptor  `json:"suggested_policies,omitempty"`
	Connected        bool                `json:"connected"`
	ConnectedVariant string              `json:"connected_variant,omitempty"`
	ConnectedAt      string              `json:"connected_at,omitempty"`
}

// VariantDescriptor is one bring-your-own-token shape. Fields is
// the form schema the UI renders.
type VariantDescriptor struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Fields      []FieldDescriptor `json:"fields,omitempty"`
}

// FieldDescriptor is one input in a variant's form.
type FieldDescriptor struct {
	Name        string `json:"name"`
	Label       string `json:"label,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Help        string `json:"help,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// PolicyDescriptor is one suggested-policy entry. Applied is true
// when *every* document inside the policy file is currently live
// (the apply endpoint is all-or-nothing per policy).
type PolicyDescriptor struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Description    string `json:"description,omitempty"`
	DefaultEnabled bool   `json:"default_enabled,omitempty"`
	Applied        bool   `json:"applied"`
}

// Registry is the boot-time-frozen aggregator. The bundle data and
// the env-derived OAuth availability never change at runtime; the
// connection store is the only piece that mutates, which we re-read
// per request to pick up freshly-staged credentials.
type Registry struct {
	services      []bundles.LoadedService
	bySlug        map[string]bundles.LoadedService
	oauthAvail    map[string]bool
	connectionSvc *connections.Store
}

// New returns a Registry over loaded with the env-derived oauth
// availability frozen. svc may be nil (deployments without a
// connection store): every service then reports Connected=false.
func New(loaded []bundles.LoadedService, env map[string]string, svc *connections.Store) *Registry {
	bySlug := make(map[string]bundles.LoadedService, len(loaded))
	avail := make(map[string]bool, len(loaded))
	for _, l := range loaded {
		bySlug[l.Service.Slug] = l
		if l.OAuth != nil {
			avail[l.Service.Slug] = env[l.OAuth.ClientIDEnv] != "" && env[l.OAuth.ClientSecretEnv] != ""
		}
	}
	return &Registry{services: loaded, bySlug: bySlug, oauthAvail: avail, connectionSvc: svc}
}

// List returns one Descriptor per registered service in slug order.
func (r *Registry) List() []Descriptor {
	out := make([]Descriptor, 0, len(r.services))
	for _, l := range r.services {
		out = append(out, r.describe(l))
	}
	return out
}

// Get returns one Descriptor by slug, or ErrUnknown.
func (r *Registry) Get(slug string) (Descriptor, error) {
	l, ok := r.bySlug[slug]
	if !ok {
		return Descriptor{}, fmt.Errorf("%w: %q", ErrUnknown, slug)
	}
	return r.describe(l), nil
}

// LoadedSuggestedPolicies returns the verbatim policy-file bodies
// for the named service. Used by the apply endpoint, which needs the
// raw YAML to decode + validate. Returns ErrUnknown when slug isn't
// registered.
func (r *Registry) LoadedSuggestedPolicies(slug string) ([]bundles.LoadedSuggestedPolicy, error) {
	l, ok := r.bySlug[slug]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknown, slug)
	}
	return l.SuggestedPolicies, nil
}

func (r *Registry) describe(l bundles.LoadedService) Descriptor {
	d := Descriptor{
		Slug:           l.Service.Slug,
		Title:          l.Service.Title,
		Description:    l.Service.Description,
		BundleName:     l.BundleName,
		APIs:           append([]string(nil), l.APIs...),
		OAuthAvailable: r.oauthAvail[l.Service.Slug],
	}
	if l.OAuth != nil {
		d.OAuthScopes = l.OAuth.Scopes
	}
	for _, v := range l.TokenVariants {
		d.TokenVariants = append(d.TokenVariants, describeVariant(v))
	}
	for _, p := range l.SuggestedPolicies {
		d.SuggestedPolicy = append(d.SuggestedPolicy, describePolicy(p))
	}
	if r.connectionSvc != nil {
		// Best-effort: a read error here shouldn't break the list.
		// Unknown is the only case we explicitly expect (slug not in
		// the connection-store allow-list); everything else is a
		// real persistence error and we surface "not connected"
		// rather than swallowing it on the wire.
		conn, err := r.connectionSvc.Get(l.Service.Slug)
		if err == nil {
			d.Connected = true
			d.ConnectedVariant = conn.Variant
			d.ConnectedAt = conn.CreatedAt.Format("2006-01-02T15:04:05Z07:00")
		}
	}
	return d
}

func describeVariant(v bundles.TokenVariant) VariantDescriptor {
	fields := make([]FieldDescriptor, 0, len(v.Fields))
	for _, f := range v.Fields {
		kind := f.Kind
		if kind == "" {
			kind = "text"
		}
		fields = append(fields, FieldDescriptor{
			Name:        f.Name,
			Label:       f.Label,
			Kind:        kind,
			Placeholder: f.Placeholder,
			Help:        f.Help,
			Required:    f.Required,
		})
	}
	return VariantDescriptor{
		ID:          v.ID,
		Title:       v.Title,
		Description: v.Description,
		Fields:      fields,
	}
}

func describePolicy(p bundles.LoadedSuggestedPolicy) PolicyDescriptor {
	return PolicyDescriptor{
		ID:             p.Meta.ID,
		Title:          p.Meta.Title,
		Description:    p.Meta.Description,
		DefaultEnabled: p.Meta.DefaultEnabled,
		// Applied state is set by the HTTP layer after consulting the
		// live policies.Service; the aggregator has no access to it.
	}
}
