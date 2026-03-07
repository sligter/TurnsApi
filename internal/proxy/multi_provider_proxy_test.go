package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"turnsapi/internal"
	"turnsapi/internal/keymanager"
	"turnsapi/internal/providers"
	"turnsapi/internal/ratelimit"
	"turnsapi/internal/router"

	"github.com/gin-gonic/gin"
)

type mockProviderFactory struct{}

func (f *mockProviderFactory) CreateProvider(config *providers.ProviderConfig) (providers.Provider, error) {
	return &mockProvider{config: config}, nil
}

func (f *mockProviderFactory) GetSupportedTypes() []string {
	return []string{"openai"}
}

type mockProvider struct {
	config *providers.ProviderConfig
}

func (p *mockProvider) GetProviderType() string {
	return p.config.ProviderType
}

func (p *mockProvider) ChatCompletion(ctx context.Context, req *providers.ChatCompletionRequest) (*providers.ChatCompletionResponse, error) {
	return &providers.ChatCompletionResponse{
		ID:      "resp-mock",
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
		Choices: []providers.ChatCompletionChoice{
			{
				Index: 0,
				Message: providers.ChatCompletionMessage{
					Role:    "assistant",
					Content: p.config.BaseURL + "|" + p.config.APIKey,
				},
				FinishReason: "stop",
			},
		},
		Usage: providers.Usage{
			PromptTokens:     1,
			CompletionTokens: 1,
			TotalTokens:      2,
		},
	}, nil
}

func (p *mockProvider) ChatCompletionStream(ctx context.Context, req *providers.ChatCompletionRequest) (<-chan providers.StreamResponse, error) {
	ch := make(chan providers.StreamResponse)
	close(ch)
	return ch, nil
}

func (p *mockProvider) ChatCompletionStreamNative(ctx context.Context, req *providers.ChatCompletionRequest) (<-chan providers.StreamResponse, error) {
	return p.ChatCompletionStream(ctx, req)
}

func (p *mockProvider) GetModels(ctx context.Context) (interface{}, error) {
	return nil, nil
}

func (p *mockProvider) HealthCheck(ctx context.Context) error {
	return nil
}

func (p *mockProvider) TransformRequest(req *providers.ChatCompletionRequest) (interface{}, error) {
	return req, nil
}

func (p *mockProvider) TransformResponse(resp interface{}) (*providers.ChatCompletionResponse, error) {
	return resp.(*providers.ChatCompletionResponse), nil
}

func (p *mockProvider) CreateHTTPRequest(ctx context.Context, endpoint string, body interface{}) (*http.Request, error) {
	return http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
}

func (p *mockProvider) ParseHTTPResponse(resp *http.Response) (interface{}, error) {
	return nil, nil
}

func TestHandleRequestWithSmartFailover_RotatesGroupsThenKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &internal.Config{
		UserGroups: map[string]*internal.UserGroup{
			"g1": {
				Name:             "group-1",
				ProviderType:     "openai",
				BaseURL:          "g1",
				Enabled:          true,
				Timeout:          5 * time.Second,
				MaxRetries:       1,
				RotationStrategy: "round_robin",
				Models:           []string{"gpt-4o-mini"},
				APIKeys:          []string{"g1k1", "g1k2"},
				Headers:          map[string]string{},
				RequestParams:    map[string]interface{}{},
				ModelMappings:    map[string]string{},
			},
			"g2": {
				Name:             "group-2",
				ProviderType:     "openai",
				BaseURL:          "g2",
				Enabled:          true,
				Timeout:          5 * time.Second,
				MaxRetries:       1,
				RotationStrategy: "round_robin",
				Models:           []string{"gpt-4o-mini"},
				APIKeys:          []string{"g2k1", "g2k2"},
				Headers:          map[string]string{},
				RequestParams:    map[string]interface{}{},
				ModelMappings:    map[string]string{},
			},
		},
	}

	keyMgr := keymanager.NewMultiGroupKeyManager(cfg)
	providerMgr := providers.NewProviderManager(&mockProviderFactory{})
	providerRouter := router.NewProviderRouter(cfg, providerMgr)
	proxy := &MultiProviderProxy{
		config:          cfg,
		keyManager:      keyMgr,
		providerManager: providerMgr,
		providerRouter:  providerRouter,
		rpmLimiter:      ratelimit.NewRPMLimiter(),
		groupRotations:  make(map[string]int),
	}

	expected := []string{
		"g1|g1k1",
		"g2|g2k1",
		"g1|g1k2",
		"g2|g2k2",
	}

	for i, want := range expected {
		got := executeChatCompletion(t, proxy, &router.RouteRequest{Model: "gpt-4o-mini"})
		if got != want {
			t.Fatalf("request %d content = %q, want %q", i+1, got, want)
		}
	}
}

func TestHandleRequestWithSmartFailover_HonorsExplicitProviderGroup(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &internal.Config{
		UserGroups: map[string]*internal.UserGroup{
			"g1": {
				Name:             "group-1",
				ProviderType:     "openai",
				BaseURL:          "g1",
				Enabled:          true,
				Timeout:          5 * time.Second,
				MaxRetries:       1,
				RotationStrategy: "round_robin",
				Models:           []string{"gpt-4o-mini"},
				APIKeys:          []string{"g1k1"},
				Headers:          map[string]string{},
				RequestParams:    map[string]interface{}{},
				ModelMappings:    map[string]string{},
			},
			"g2": {
				Name:             "group-2",
				ProviderType:     "openai",
				BaseURL:          "g2",
				Enabled:          true,
				Timeout:          5 * time.Second,
				MaxRetries:       1,
				RotationStrategy: "round_robin",
				Models:           []string{"gpt-4o-mini"},
				APIKeys:          []string{"g2k1"},
				Headers:          map[string]string{},
				RequestParams:    map[string]interface{}{},
				ModelMappings:    map[string]string{},
			},
		},
	}

	keyMgr := keymanager.NewMultiGroupKeyManager(cfg)
	providerMgr := providers.NewProviderManager(&mockProviderFactory{})
	providerRouter := router.NewProviderRouter(cfg, providerMgr)
	proxy := &MultiProviderProxy{
		config:          cfg,
		keyManager:      keyMgr,
		providerManager: providerMgr,
		providerRouter:  providerRouter,
		rpmLimiter:      ratelimit.NewRPMLimiter(),
		groupRotations:  make(map[string]int),
	}

	got := executeChatCompletion(t, proxy, &router.RouteRequest{
		Model:         "gpt-4o-mini",
		ProviderGroup: "g2",
	})

	if got != "g2|g2k1" {
		t.Fatalf("explicit provider group result = %q, want %q", got, "g2|g2k1")
	}
}

func executeChatCompletion(t *testing.T, proxy *MultiProviderProxy, routeReq *router.RouteRequest) string {
	t.Helper()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req := &providers.ChatCompletionRequest{
		Model: "gpt-4o-mini",
		Messages: []providers.ChatMessage{
			{Role: "user", Content: "hello"},
		},
	}

	if !proxy.handleRequestWithSmartFailover(ctx, req, routeReq, time.Now()) {
		t.Fatalf("handleRequestWithSmartFailover returned false")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}

	var resp providers.ChatCompletionResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.Choices) == 0 {
		t.Fatalf("response choices is empty")
	}

	return resp.Choices[0].Message.Content
}
