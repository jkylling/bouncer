// Package services projects per-bundle service metadata (slug, title,
// description, bring-your-own-token variants) into the JSON shape the
// /_api/services surface returns.
//
// The package is a small read-only aggregator: it does no I/O on its
// own, taking the LoadedService snapshot from the bundles loader.
package services

import (
	"errors"
	"fmt"

	"github.com/jkylling/bouncer/internal/control/bundles"
)

// Sentinel errors. The HTTP layer maps these onto statuses.
var (
	ErrUnknown = errors.New("unknown service")
)

// Descriptor is the JSON shape one service exposes on /_api/services.
// Slug is the canonical key; TokenVariants is the form schema the
// tokens screen renders.
type Descriptor struct {
	Slug          string              `json:"slug"`
	Title         string              `json:"title"`
	Description   string              `json:"description,omitempty"`
	BundleName    string              `json:"bundle_name,omitempty"`
	APIs          []string            `json:"apis,omitempty"`
	TokenVariants []VariantDescriptor `json:"token_variants,omitempty"`
}

// VariantDescriptor is one bring-your-own-token shape. Fields is
// the form schema the UI renders. Refresh is non-nil for variants
// that emit a refresh JWT (the operator pastes refresh_token /
// client_id / client_secret); nil for plain access-token variants.
type VariantDescriptor struct {
	ID          string             `json:"id"`
	Title       string             `json:"title"`
	Description string             `json:"description,omitempty"`
	Refresh     *RefreshDescriptor `json:"refresh,omitempty"`
	Fields      []FieldDescriptor  `json:"fields,omitempty"`
}

// RefreshDescriptor mirrors bundles.RefreshConfig.
type RefreshDescriptor struct {
	TokenURL string `json:"token_url"`
}

// FieldDescriptor is one input in a variant's form.
type FieldDescriptor struct {
	Name        string `json:"name"`
	Label       string `json:"label,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
	Help        string `json:"help,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Header      string `json:"header,omitempty"`
	Template    string `json:"template,omitempty"`
}

// Registry is the boot-time-frozen aggregator over the loaded service
// blocks.
type Registry struct {
	services []bundles.LoadedService
	bySlug   map[string]bundles.LoadedService
}

// New returns a Registry over loaded.
func New(loaded []bundles.LoadedService) *Registry {
	bySlug := make(map[string]bundles.LoadedService, len(loaded))
	for _, l := range loaded {
		bySlug[l.Service.Slug] = l
	}
	return &Registry{services: loaded, bySlug: bySlug}
}

// List returns one Descriptor per registered service in slug order.
func (r *Registry) List() []Descriptor {
	out := make([]Descriptor, 0, len(r.services))
	for _, l := range r.services {
		out = append(out, describe(l))
	}
	return out
}

// Get returns one Descriptor by slug, or ErrUnknown.
func (r *Registry) Get(slug string) (Descriptor, error) {
	l, ok := r.bySlug[slug]
	if !ok {
		return Descriptor{}, fmt.Errorf("%w: %q", ErrUnknown, slug)
	}
	return describe(l), nil
}

// Variant returns the named token variant for the named service.
// Used by the tokens screen's issue handler to resolve the variant
// the operator submitted.
func (r *Registry) Variant(slug, variant string) (bundles.TokenVariant, error) {
	l, ok := r.bySlug[slug]
	if !ok {
		return bundles.TokenVariant{}, fmt.Errorf("%w: %q", ErrUnknown, slug)
	}
	for _, v := range l.TokenVariants {
		if v.ID == variant {
			return v, nil
		}
	}
	return bundles.TokenVariant{}, fmt.Errorf("%w: variant %q not found on %q", ErrUnknown, variant, slug)
}

func describe(l bundles.LoadedService) Descriptor {
	d := Descriptor{
		Slug:        l.Service.Slug,
		Title:       l.Service.Title,
		Description: l.Service.Description,
		BundleName:  l.BundleName,
		APIs:        append([]string(nil), l.APIs...),
	}
	for _, v := range l.TokenVariants {
		d.TokenVariants = append(d.TokenVariants, describeVariant(v))
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
			Header:      f.Header,
			Template:    f.Template,
		})
	}
	out := VariantDescriptor{
		ID:          v.ID,
		Title:       v.Title,
		Description: v.Description,
		Fields:      fields,
	}
	if v.Refresh != nil {
		out.Refresh = &RefreshDescriptor{TokenURL: v.Refresh.TokenURL}
	}
	return out
}
