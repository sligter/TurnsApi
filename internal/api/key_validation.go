package api

import (
	"errors"
	"strings"

	"turnsapi/internal/providers"
)

type KeyValidationStatus string

const (
	KeyValidationValid   KeyValidationStatus = "valid"
	KeyValidationInvalid KeyValidationStatus = "invalid"
	KeyValidationUnknown KeyValidationStatus = "unknown"
)

func classifyKeyValidation(err error) (KeyValidationStatus, *bool) {
	if err == nil {
		isValid := true
		return KeyValidationValid, &isValid
	}

	if isKeyAuthInvalidError(err) {
		isValid := false
		return KeyValidationInvalid, &isValid
	}

	// 包括 429 / rate limit / quota / timeout / 5xx / 网络错误等都属于“未知”，不应据此判定密钥无效。
	return KeyValidationUnknown, nil
}

func isKeyAuthInvalidError(err error) bool {
	if err == nil {
		return false
	}

	var tcErr *providers.ToolCallError
	if errors.As(err, &tcErr) {
		switch tcErr.Type {
		case "authentication_error", "permission_error":
			return true
		}
	}

	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "401") ||
		strings.Contains(msg, "403") ||
		strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "forbidden") ||
		strings.Contains(msg, "invalid api key") ||
		strings.Contains(msg, "invalid_api_key") ||
		strings.Contains(msg, "authentication failed") ||
		strings.Contains(msg, "api key not found")
}
