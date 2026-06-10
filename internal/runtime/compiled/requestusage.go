package compiled

import (
	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
)

// astUsesRequestBody reports whether the compiled expression can
// observe `request.body`. The data plane uses this signal — folded up
// through Action / Meta / Policy / APIRuntime — to decide whether an
// inbound request body must be buffered and parsed for policy
// evaluation or can stream straight upstream.
//
// Detection is conservative in the safe direction: selecting any
// *other* field off `request` (method, path, query, ...) does not
// count, but using the whole `request` value in any other position —
// function argument, comparison, iteration, struct field — counts as
// "uses body", because the value could carry the body somewhere we
// can't see. A false positive only costs buffering; a false negative
// would evaluate a body-gated policy against an absent body.
func astUsesRequestBody(a *cel.Ast) bool {
	return exprUsesRequestBody(a.NativeRep().Expr())
}

func exprUsesRequestBody(e celast.Expr) bool {
	switch e.Kind() {
	case celast.SelectKind:
		sel := e.AsSelect()
		op := sel.Operand()
		if op.Kind() == celast.IdentKind && op.AsIdent() == "request" {
			return sel.FieldName() == "body"
		}
		return exprUsesRequestBody(op)
	case celast.IdentKind:
		// A bare `request` outside a field selection: whole-value use.
		return e.AsIdent() == "request"
	case celast.CallKind:
		call := e.AsCall()
		if call.IsMemberFunction() && exprUsesRequestBody(call.Target()) {
			return true
		}
		for _, arg := range call.Args() {
			if exprUsesRequestBody(arg) {
				return true
			}
		}
		return false
	case celast.ListKind:
		for _, el := range e.AsList().Elements() {
			if exprUsesRequestBody(el) {
				return true
			}
		}
		return false
	case celast.MapKind:
		for _, entry := range e.AsMap().Entries() {
			me := entry.AsMapEntry()
			if exprUsesRequestBody(me.Key()) || exprUsesRequestBody(me.Value()) {
				return true
			}
		}
		return false
	case celast.StructKind:
		for _, field := range e.AsStruct().Fields() {
			if exprUsesRequestBody(field.AsStructField().Value()) {
				return true
			}
		}
		return false
	case celast.ComprehensionKind:
		comp := e.AsComprehension()
		return exprUsesRequestBody(comp.IterRange()) ||
			exprUsesRequestBody(comp.AccuInit()) ||
			exprUsesRequestBody(comp.LoopCondition()) ||
			exprUsesRequestBody(comp.LoopStep()) ||
			exprUsesRequestBody(comp.Result())
	default:
		return false
	}
}
