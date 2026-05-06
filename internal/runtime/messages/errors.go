package messages

import (
	"errors"
	"fmt"
)

var (
	errNilType       = errors.New("messages: nil Type")
	errEmptyFullName = errors.New("messages: Type.FullName is empty")
)

type duplicateTypeError struct{ name string }

func (e *duplicateTypeError) Error() string {
	return fmt.Sprintf("messages: type %q already registered", e.name)
}

type unknownTypeError struct{ name string }

func (e *unknownTypeError) Error() string {
	return fmt.Sprintf("messages: unknown type %q", e.name)
}
