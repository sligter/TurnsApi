package api

import (
	"fmt"
	"testing"

	"turnsapi/internal/providers"
)

func TestClassifyKeyValidation(t *testing.T) {
	t.Run("nil error is valid", func(t *testing.T) {
		status, isValid := classifyKeyValidation(nil)
		if status != KeyValidationValid {
			t.Fatalf("status = %q, want %q", status, KeyValidationValid)
		}
		if isValid == nil || *isValid != true {
			t.Fatalf("isValid = %#v, want true", isValid)
		}
	})

	t.Run("auth error is invalid", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", &providers.ToolCallError{
			Type:    "authentication_error",
			Code:    "unauthorized",
			Message: "Invalid API key",
		})

		status, isValid := classifyKeyValidation(err)
		if status != KeyValidationInvalid {
			t.Fatalf("status = %q, want %q", status, KeyValidationInvalid)
		}
		if isValid == nil || *isValid != false {
			t.Fatalf("isValid = %#v, want false", isValid)
		}
	})

	t.Run("rate limit error is unknown", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", &providers.ToolCallError{
			Type:    "rate_limit_error",
			Code:    "rate_limit_exceeded",
			Message: "Rate limit exceeded - please try again later",
		})

		status, isValid := classifyKeyValidation(err)
		if status != KeyValidationUnknown {
			t.Fatalf("status = %q, want %q", status, KeyValidationUnknown)
		}
		if isValid != nil {
			t.Fatalf("isValid = %#v, want nil", isValid)
		}
	})

	t.Run("HTTP 401 string is invalid", func(t *testing.T) {
		status, isValid := classifyKeyValidation(fmt.Errorf("HTTP 401: Unauthorized"))
		if status != KeyValidationInvalid {
			t.Fatalf("status = %q, want %q", status, KeyValidationInvalid)
		}
		if isValid == nil || *isValid != false {
			t.Fatalf("isValid = %#v, want false", isValid)
		}
	})
}
