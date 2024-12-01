package types

import "fmt"

// ErrUnimplemented describes an error where a function, version or any other thing isn't implemented.
type ErrUnimplemented struct {
	// Method is used to store the name of the function, ... that isn't implemented, or a text describing it.
	Method string
}

// Error returns custom error text.
func (e ErrUnimplemented) Error() string {
	return fmt.Sprintf("not implemented: %s", e.Method)
}

// NewNotImplementedErr returns a new ErrUnimplemented struct holding the specified method string.
func NewNotImplementedErr(method string) *ErrUnimplemented {
	return &ErrUnimplemented{
		Method: method,
	}
}

type ErrBadKey struct {
	Message string
}

func (e ErrBadKey) Error() string {
	return fmt.Sprintf("bad key: %s", e.Message)
}

func NewBadKeyErr(message string) *ErrBadKey {
	return &ErrBadKey{
		Message: message,
	}
}
