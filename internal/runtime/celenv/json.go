// Package celenv builds CEL environments and translates between CEL values
// and protobuf wire types used by the runtime.
package celenv

import (
	"fmt"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"

	structpb "google.golang.org/protobuf/types/known/structpb"
)

// maxSafeInt is the largest integer that round-trips losslessly through
// a float64 — JSON numbers are float64-encoded, so any integer with a
// larger magnitude would lose precision. Matches JS's
// Number.MAX_SAFE_INTEGER convention (2^53 − 1).
const maxSafeInt = 1<<53 - 1

// celToPbValue recursively translates a CEL value into a google.protobuf.Value.
// Used by the HTTP helper bindings to encode CEL bodies into MetaRequest.Body.
// Fails on non-string map keys or unsupported kinds (struct, type, error, etc.).
func celToPbValue(v ref.Val) (*structpb.Value, error) {
	if v == nil {
		return structpb.NewNullValue(), nil
	}
	// Optional values: unwrap Some, fall back to null for None.
	if opt, ok := v.(*types.Optional); ok {
		if !opt.HasValue() {
			return structpb.NewNullValue(), nil
		}
		return celToPbValue(opt.GetValue())
	}
	switch x := v.(type) {
	case types.Null:
		return structpb.NewNullValue(), nil
	case types.Bool:
		return structpb.NewBoolValue(bool(x)), nil
	case types.Int:
		// structpb.Value's number is a float64; ints outside ±maxSafeInt
		// cannot round-trip exactly. Reject rather than silently lose
		// precision.
		if x > maxSafeInt || x < -maxSafeInt {
			return nil, fmt.Errorf("integer %d exceeds JSON safe range (±2^53 − 1)", int64(x))
		}
		return structpb.NewNumberValue(float64(x)), nil
	case types.Uint:
		if x > maxSafeInt {
			return nil, fmt.Errorf("unsigned integer %d exceeds JSON safe range (2^53 − 1)", uint64(x))
		}
		return structpb.NewNumberValue(float64(x)), nil
	case types.Double:
		return structpb.NewNumberValue(float64(x)), nil
	case types.String:
		return structpb.NewStringValue(string(x)), nil
	case traits.Lister:
		var values []*structpb.Value
		it := x.Iterator()
		for it.HasNext() == types.True {
			elem, err := celToPbValue(it.Next())
			if err != nil {
				return nil, err
			}
			values = append(values, elem)
		}
		return structpb.NewListValue(&structpb.ListValue{Values: values}), nil
	case traits.Mapper:
		fields := map[string]*structpb.Value{}
		it := x.Iterator()
		for it.HasNext() == types.True {
			k := it.Next()
			ks, ok := k.(types.String)
			if !ok {
				return nil, fmt.Errorf("JSON body requires string map keys, got %s", k.Type().TypeName())
			}
			val, ok2 := x.Find(k)
			if !ok2 {
				return nil, fmt.Errorf("map key %q vanished between iteration and lookup", string(ks))
			}
			pb, err := celToPbValue(val)
			if err != nil {
				return nil, err
			}
			fields[string(ks)] = pb
		}
		return structpb.NewStructValue(&structpb.Struct{Fields: fields}), nil
	}
	return nil, fmt.Errorf("cannot encode CEL %T as JSON value", v)
}
