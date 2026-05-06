package celenv

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	structpb "google.golang.org/protobuf/types/known/structpb"
)

// TestCelToPbValueTable covers every kind branch celToPbValue handles
// plus the boundary cases the doc comments promise. Each case asserts
// the kind of the returned structpb.Value and (where applicable) its
// payload — together they pin the contract the recorder and meta-call
// path depend on.
func TestCelToPbValueTable(t *testing.T) {
	cases := []struct {
		name      string
		in        ref.Val
		want      func(*testing.T, *structpb.Value)
		expectErr bool
	}{
		{
			name: "nil → null",
			in:   nil,
			want: assertKind[*structpb.Value_NullValue],
		},
		{
			name: "bool true",
			in:   types.Bool(true),
			want: assertBool(true),
		},
		{
			name: "int positive",
			in:   types.Int(7),
			want: assertNumber(7),
		},
		{
			name: "int negative",
			in:   types.Int(-3),
			want: assertNumber(-3),
		},
		{
			name: "uint",
			in:   types.Uint(42),
			want: assertNumber(42),
		},
		{
			name: "double",
			in:   types.Double(3.14),
			want: assertNumber(3.14),
		},
		{
			name: "string",
			in:   types.String("x"),
			want: assertString("x"),
		},
		{
			name: "null",
			in:   types.NullValue,
			want: assertKind[*structpb.Value_NullValue],
		},
		{
			name:      "int above safe bound",
			in:        types.Int(1 << 53),
			expectErr: true,
		},
		{
			name:      "int below safe bound",
			in:        types.Int(-(1 << 53)),
			expectErr: true,
		},
		{
			name:      "uint above safe bound",
			in:        types.Uint(1 << 53),
			expectErr: true,
		},
		{
			name: "int at safe boundary",
			in:   types.Int(1<<53 - 1),
			want: assertNumber(1<<53 - 1),
		},
		{
			name: "empty list",
			in:   types.DefaultTypeAdapter.NativeToValue([]any{}),
			want: func(t *testing.T, v *structpb.Value) {
				lv := v.GetListValue()
				if lv == nil || len(lv.Values) != 0 {
					t.Errorf("list: %v", v)
				}
			},
		},
		{
			name: "empty map",
			in:   types.DefaultTypeAdapter.NativeToValue(map[string]any{}),
			want: func(t *testing.T, v *structpb.Value) {
				sv := v.GetStructValue()
				if sv == nil || len(sv.Fields) != 0 {
					t.Errorf("struct: %v", v)
				}
			},
		},
		{
			name: "optional none → null",
			in:   types.OptionalNone,
			want: assertKind[*structpb.Value_NullValue],
		},
		{
			name: "optional some(bool)",
			in:   types.OptionalOf(types.Bool(true)),
			want: assertBool(true),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := celToPbValue(tc.in)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("want error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			tc.want(t, got)
		})
	}
}

// TestCelToPbValueNestedMapWithList exercises the recursive paths
// (map → list → string) in one go.
func TestCelToPbValueNestedMapWithList(t *testing.T) {
	m := types.DefaultTypeAdapter.NativeToValue(map[string]any{
		"name": "alice",
		"tags": []any{"a", "b"},
	})
	pb, err := celToPbValue(m)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	s := pb.GetStructValue()
	if s == nil {
		t.Fatal("expected Struct")
	}
	if s.Fields["name"].GetStringValue() != "alice" {
		t.Errorf("name: %v", s.Fields["name"])
	}
	tags := s.Fields["tags"].GetListValue()
	if tags == nil || len(tags.Values) != 2 {
		t.Errorf("tags: %v", s.Fields["tags"])
	}
}

// TestCelToPbValueNonStringMapKeyErrors pins the failure-closed path
// for non-string map keys — a JSON body cannot represent them.
func TestCelToPbValueNonStringMapKeyErrors(t *testing.T) {
	m := types.DefaultTypeAdapter.NativeToValue(map[int64]any{1: "x"})
	_, err := celToPbValue(m)
	if err == nil {
		t.Fatal("expected error")
	}
}

func assertKind[T any](t *testing.T, v *structpb.Value) {
	t.Helper()
	if _, ok := v.GetKind().(T); !ok {
		var zero T
		t.Errorf("kind = %T, want %T", v.GetKind(), zero)
	}
}

func assertBool(want bool) func(*testing.T, *structpb.Value) {
	return func(t *testing.T, v *structpb.Value) {
		t.Helper()
		if v.GetBoolValue() != want {
			t.Errorf("bool = %v, want %v", v.GetBoolValue(), want)
		}
	}
}

func assertNumber(want float64) func(*testing.T, *structpb.Value) {
	return func(t *testing.T, v *structpb.Value) {
		t.Helper()
		if v.GetNumberValue() != want {
			t.Errorf("num = %v, want %v", v.GetNumberValue(), want)
		}
	}
}

func assertString(want string) func(*testing.T, *structpb.Value) {
	return func(t *testing.T, v *structpb.Value) {
		t.Helper()
		if v.GetStringValue() != want {
			t.Errorf("str = %q, want %q", v.GetStringValue(), want)
		}
	}
}
