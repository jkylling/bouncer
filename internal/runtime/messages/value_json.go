package messages

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
)

// MarshalJSON serialises this Value into a stable shape the traffic
// recorder can persist:
//
//	{
//	  "type":    "<api>.<meta>",
//	  "inputs":  { ... },
//	  "outputs": { ... }   // only present on a full-view Value
//	}
//
// Output fields populated lazily by the policy condition land in
// `outputs`; unread fields are omitted. The walk recurses into
// nested *Value entries so chained `parent.parent` accesses serialise
// fully. Non-Value field values fall back to encoding/json's native
// rendering via cel-go's ConvertToNative; types it can't convert
// degrade to a string fingerprint rather than failing the encode.
//
// The shape is documented because the policy-from-request flow round
// trips it: a future helper will rebuild a CEL equality predicate
// from the same JSON.
func (v *Value) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.toJSONShape())
}

// toJSONShape produces the map encoded by MarshalJSON. Exposed for
// tests so they can assert on the structure without round-tripping
// through json.Marshal first. The "type" key is the meta's FullName
// — not nameStr, which carries the .__input__ suffix on input views
// — so consumers see one stable identifier per meta regardless of
// view.
func (v *Value) toJSONShape() map[string]any {
	out := map[string]any{
		"type":   v.typ.FullName,
		"inputs": fieldMapToJSON(v.inputs),
	}
	if v.view == fullView && len(v.outputs) > 0 {
		out["outputs"] = fieldMapToJSON(v.outputs)
	}
	return out
}

// fieldMapToJSON walks an inputs/outputs map. Sorted by key so the
// output is deterministic across Go map iteration orders — a stable
// shape matters for the recorder's diff/replay flows and for tests
// that compare expected JSON byte-for-byte.
func fieldMapToJSON(m map[string]ref.Val) map[string]any {
	if len(m) == 0 {
		return map[string]any{}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		out[k] = refValToJSON(m[k])
	}
	return out
}

// refValToJSON lowers a ref.Val into something encoding/json can
// emit. *Value recurses; lists and maps walk via cel-go's iterators
// so a list of nested values renders correctly.
func refValToJSON(v ref.Val) any {
	if v == nil {
		return nil
	}
	switch x := v.(type) {
	case *Value:
		return x.toJSONShape()
	case types.Null:
		return nil
	}
	if list, ok := v.(traits.Lister); ok {
		out := []any{}
		it := list.Iterator()
		for it.HasNext() == types.True {
			out = append(out, refValToJSON(it.Next()))
		}
		return out
	}
	if m, ok := v.(traits.Mapper); ok {
		out := map[string]any{}
		it := m.Iterator()
		for it.HasNext() == types.True {
			k := it.Next()
			ks := mapperKeyToString(k)
			out[ks] = refValToJSON(m.Get(k))
		}
		return out
	}
	if native, err := v.ConvertToNative(reflect.TypeOf((*any)(nil)).Elem()); err == nil {
		return native
	}
	return fmt.Sprint(v.Value())
}

// mapperKeyToString stringifies a cel-go map key. JSON only allows
// string keys, so non-string keys (rare in policy-time values) are
// rendered via fmt.Sprint to keep the encode lossy-but-stable.
func mapperKeyToString(k ref.Val) string {
	if s, ok := k.(types.String); ok {
		return string(s)
	}
	return fmt.Sprint(k.Value())
}
