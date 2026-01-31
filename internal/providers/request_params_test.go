package providers

import (
	"encoding/json"
	"testing"
)

func TestChatCompletionRequestApplyRequestParamsForcesOverride(t *testing.T) {
	temp := 0.1
	topP := 0.2
	maxTokens := 100

	req := &ChatCompletionRequest{
		Model: "gpt-4o",
		Messages: []ChatMessage{
			{Role: "user", Content: "hi"},
		},
		Temperature: &temp,
		TopP:        &topP,
		MaxTokens:   &maxTokens,
		Stream:      true,
		Extra: map[string]interface{}{
			"response_format": map[string]interface{}{"type": "text"},
		},
	}

	req.ApplyRequestParams(map[string]interface{}{
		"temperature":     1, // int should be accepted
		"top_p":           0.9,
		"max_tokens":      2000,
		"stream":          false,
		"response_format": map[string]interface{}{"type": "json_object"},
	})

	if req.Temperature == nil || *req.Temperature != 1.0 {
		t.Fatalf("expected temperature=1.0, got %v", req.Temperature)
	}
	if req.TopP == nil || *req.TopP != 0.9 {
		t.Fatalf("expected top_p=0.9, got %v", req.TopP)
	}
	if req.MaxTokens == nil || *req.MaxTokens != 2000 {
		t.Fatalf("expected max_tokens=2000, got %v", req.MaxTokens)
	}
	if req.Stream {
		t.Fatalf("expected stream=false, got true")
	}

	if req.Extra == nil {
		t.Fatalf("expected Extra to be non-nil")
	}
	rf, ok := req.Extra["response_format"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected response_format to be map, got %T", req.Extra["response_format"])
	}
	if rf["type"] != "json_object" {
		t.Fatalf("expected response_format.type=json_object, got %v", rf["type"])
	}
}

func TestChatCompletionRequestMarshalJSONIncludesExtra(t *testing.T) {
	req := &ChatCompletionRequest{
		Model: "gpt-4o",
		Messages: []ChatMessage{
			{Role: "user", Content: "hi"},
		},
		Extra: map[string]interface{}{
			"response_format": map[string]interface{}{"type": "json_object"},
			"model":           "bad-model", // should not override typed field
		},
	}

	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if m["model"] != "gpt-4o" {
		t.Fatalf("expected model=gpt-4o, got %v", m["model"])
	}
	if _, ok := m["response_format"]; !ok {
		t.Fatalf("expected response_format to exist in marshaled json")
	}
}
