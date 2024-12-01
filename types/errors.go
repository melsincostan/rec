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

// ErrBadKey represents an error for an invalid key (wrong length, ...).
type ErrBadKey struct {
	// Message allows adding a custom message to the error to specify what is wrong with the key
	Message string
}

// Error returns custom error text.
func (e ErrBadKey) Error() string {
	return fmt.Sprintf("bad key: %s", e.Message)
}

// NewBadKeyErr returns the error type and sets the message to what is passed.
func NewBadKeyErr(message string) *ErrBadKey {
	return &ErrBadKey{
		Message: message,
	}
}

// ErrBadIntegrity represents an error when the computed integrity doesn't match the expected value.
type ErrBadIntegrity struct{}

// Error returns a custom error message.
func (e ErrBadIntegrity) Error() string {
	return "integrity not valid"
}

// NewBadIntegrityErr returns a pointer to an instance of ErrBadIntegrity.
func NewBadIntegrityErr() *ErrBadIntegrity {
	return &ErrBadIntegrity{}
}

// ErrBadRotation represents an error when attempting a rotation (most likely trying to go to a newer version < to the older one).
type ErrBadRotation struct {
	// Message is a field for an informative message about why the rotation couldn't be made.
	Message string
}

// Error implements the error interface for ErrBadRotation.
func (e ErrBadRotation) Error() string {
	return fmt.Sprintf("impossible to rotate the record: %s", e.Message)
}

// NewBadRotationErr returns a pointer to an ErrBadRotation object with the Message field set to the provided message.
func NewBadRotationErr(message string) *ErrBadRotation {
	return &ErrBadRotation{
		Message: message,
	}
}
