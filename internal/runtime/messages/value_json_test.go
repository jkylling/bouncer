package messages

import (
	"encoding/json"
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValueMarshalJSONInputView(t *testing.T) {
	r := newTestRegistry(t)
	v, err := r.NewInputValue("google.mail.message", map[string]ref.Val{
		"id": types.String("abc"),
	})
	require.NoError(t, err)

	got, err := json.Marshal(v)
	require.NoError(t, err)

	assert.JSONEq(t, `{
	  "type":   "google.mail.message",
	  "inputs": {"id": "abc"}
	}`, string(got))
}

func TestValueMarshalJSONFullViewWithPopulatedOutputs(t *testing.T) {
	r := newTestRegistry(t)
	v, err := r.NewFullValue("google.mail.message", map[string]ref.Val{
		"id": types.String("m1"),
	})
	require.NoError(t, err)
	v.SetCompleter(func() error {
		v.SetField("sender", types.String("alice@example.com"))
		v.SetField("subject", types.String("hi"))
		return nil
	})
	// Trigger completion so outputs land in the JSON.
	v.Get(types.String("sender"))

	got, err := json.Marshal(v)
	require.NoError(t, err)

	assert.JSONEq(t, `{
	  "type":    "google.mail.message",
	  "inputs":  {"id": "m1"},
	  "outputs": {"sender": "alice@example.com", "subject": "hi"}
	}`, string(got))
}

func TestValueMarshalJSONRecurses(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(&Type{
		FullName:     "x.parent",
		InputFields:  []string{"id"},
		OutputFields: []string{"name"},
	}))
	require.NoError(t, r.Register(&Type{
		FullName:     "x.file",
		InputFields:  []string{"id"},
		OutputFields: []string{"parent"},
	}))

	parent, err := r.NewFullValue("x.parent", map[string]ref.Val{"id": types.String("p1")})
	require.NoError(t, err)
	parent.SetCompleter(func() error {
		parent.SetField("name", types.String("docs"))
		return nil
	})
	parent.Get(types.String("name"))

	file, err := r.NewFullValue("x.file", map[string]ref.Val{"id": types.String("f1")})
	require.NoError(t, err)
	file.SetCompleter(func() error {
		file.SetField("parent", parent)
		return nil
	})
	file.Get(types.String("parent"))

	got, err := json.Marshal(file)
	require.NoError(t, err)

	assert.JSONEq(t, `{
	  "type":    "x.file",
	  "inputs":  {"id": "f1"},
	  "outputs": {
	    "parent": {
	      "type":    "x.parent",
	      "inputs":  {"id": "p1"},
	      "outputs": {"name": "docs"}
	    }
	  }
	}`, string(got))
}

func TestValueMarshalJSONOmitsUnreadOutputs(t *testing.T) {
	r := newTestRegistry(t)
	v, err := r.NewFullValue("google.mail.message", map[string]ref.Val{
		"id": types.String("m"),
	})
	require.NoError(t, err)
	// Completer never fires — outputs map stays empty, so the JSON
	// shape must omit the "outputs" key entirely. This is the bit
	// the user cares about: the recorder shows what the policy
	// *actually saw*, not the meta type's full shape.
	got, err := json.Marshal(v)
	require.NoError(t, err)

	assert.JSONEq(t, `{
	  "type":   "google.mail.message",
	  "inputs": {"id": "m"}
	}`, string(got))
}
