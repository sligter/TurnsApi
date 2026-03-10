package providers

import "testing"

func TestBuildResponsesRequestBodyMapsReasoningEffort(t *testing.T) {
	provider := NewOpenAIProvider(&ProviderConfig{
		BaseURL: "https://api.openai.com/v1",
	})

	req := &ChatCompletionRequest{
		Model: "gpt-5",
		Messages: []ChatMessage{
			{Role: "user", Content: "hi"},
		},
		Extra: map[string]interface{}{
			"reasoning_effort": "xhigh",
		},
	}

	body, err := provider.buildResponsesRequestBody(req, false)
	if err != nil {
		t.Fatalf("buildResponsesRequestBody: %v", err)
	}

	if _, exists := body["reasoning_effort"]; exists {
		t.Fatalf("expected reasoning_effort to be removed from responses body")
	}

	reasoning, ok := body["reasoning"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected reasoning map, got %T", body["reasoning"])
	}

	if reasoning["effort"] != "xhigh" {
		t.Fatalf("expected reasoning.effort=xhigh, got %v", reasoning["effort"])
	}
}

func TestPrepareChatCompletionsRequestMapsNestedReasoningEffort(t *testing.T) {
	provider := NewOpenAIProvider(&ProviderConfig{
		BaseURL: "https://api.openai.com/v1",
	})

	req := &ChatCompletionRequest{
		Model: "gpt-5",
		Messages: []ChatMessage{
			{Role: "user", Content: "hi"},
		},
		Extra: map[string]interface{}{
			"reasoning": map[string]interface{}{
				"effort":  "medium",
				"summary": "auto",
			},
		},
	}

	prepared := provider.prepareChatCompletionsRequest(req)
	if prepared == nil {
		t.Fatalf("expected prepared request")
	}

	if prepared.Extra["reasoning_effort"] != "medium" {
		t.Fatalf("expected reasoning_effort=medium, got %v", prepared.Extra["reasoning_effort"])
	}

	reasoning, ok := prepared.Extra["reasoning"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected reasoning map, got %T", prepared.Extra["reasoning"])
	}

	if _, exists := reasoning["effort"]; exists {
		t.Fatalf("expected nested reasoning.effort to be removed for chat completions")
	}

	if reasoning["summary"] != "auto" {
		t.Fatalf("expected reasoning.summary=auto, got %v", reasoning["summary"])
	}

	if _, exists := req.Extra["reasoning_effort"]; exists {
		t.Fatalf("expected original request extra to remain unchanged")
	}
}
