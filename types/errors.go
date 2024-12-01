package types

import "fmt"

type ErrUnimplemented struct {
	Method string
}

func (e ErrUnimplemented) Error() string {
	return fmt.Sprintf("Not implemented: %s", e.Method)
}

func NewNotImplementedErr(method string) *ErrUnimplemented {
	return &ErrUnimplemented{
		Method: method,
	}
}
