package providers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// OpenAIProvider OpenAI格式提供商
type OpenAIProvider struct {
	*BaseProvider
}

// NewOpenAIProvider 创建OpenAI提供商
func NewOpenAIProvider(config *ProviderConfig) *OpenAIProvider {
	return &OpenAIProvider{
		BaseProvider: NewBaseProvider(config),
	}
}

func (p *OpenAIProvider) useResponsesAPI() bool {
	return p != nil && p.Config != nil && p.Config.UseResponsesAPI
}

func joinURL(base, path string) string {
	base = strings.TrimRight(base, "/")
	path = strings.TrimLeft(path, "/")
	if base == "" {
		return "/" + path
	}
	if path == "" {
		return base
	}
	return base + "/" + path
}

func getHeaderValue(headers map[string]string, key string) (string, bool) {
	if headers == nil {
		return "", false
	}
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return "", false
}

func hasHeader(headers map[string]string, key string) bool {
	_, ok := getHeaderValue(headers, key)
	return ok
}

func setHeaderIfMissing(req *http.Request, headers map[string]string, key, value string) {
	if req == nil {
		return
	}
	if hasHeader(headers, key) {
		return
	}
	if strings.TrimSpace(req.Header.Get(key)) != "" {
		return
	}
	if strings.TrimSpace(value) == "" {
		return
	}
	req.Header.Set(key, value)
}

func maskSecret(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}
	if len(value) <= 8 {
		return "****"
	}
	return value[:4] + "****" + value[len(value)-4:]
}

func maskHeaderValue(key, value string) string {
	lower := strings.ToLower(key)
	if strings.Contains(lower, "authorization") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "bearer ") {
			return "Bearer " + maskSecret(strings.TrimSpace(value)[7:])
		}
		return maskSecret(value)
	}
	if strings.Contains(lower, "api-key") || strings.Contains(lower, "apikey") || strings.Contains(lower, "token") || strings.Contains(lower, "cookie") {
		return maskSecret(value)
	}
	return value
}

func sanitizeHeadersForLog(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vv := range h {
		if len(vv) == 0 {
			continue
		}
		val := strings.Join(vv, ",")
		out[k] = maskHeaderValue(k, val)
	}
	return out
}

func truncateForLog(body []byte, limit int) string {
	if len(body) == 0 {
		return ""
	}
	if limit <= 0 || len(body) <= limit {
		return string(body)
	}
	return string(body[:limit]) + "...(truncated)"
}

type openAIResponsesUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	TotalTokens  int `json:"total_tokens"`
}

type openAIResponsesIncompleteDetails struct {
	Reason string `json:"reason,omitempty"`
}

type openAIResponsesContentPart struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type openAIResponsesOutputItem struct {
	ID        string                       `json:"id,omitempty"`
	Type      string                       `json:"type"`
	Role      string                       `json:"role,omitempty"`
	Content   []openAIResponsesContentPart `json:"content,omitempty"`
	CallID    string                       `json:"call_id,omitempty"`
	Name      string                       `json:"name,omitempty"`
	Arguments string                       `json:"arguments,omitempty"`
}

type openAIResponsesResponse struct {
	ID                string                            `json:"id"`
	Object            string                            `json:"object"`
	CreatedAt         int64                             `json:"created_at"`
	Model             string                            `json:"model"`
	Status            string                            `json:"status"`
	Output            []openAIResponsesOutputItem       `json:"output"`
	Usage             *openAIResponsesUsage             `json:"usage,omitempty"`
	IncompleteDetails *openAIResponsesIncompleteDetails `json:"incomplete_details,omitempty"`
}

type openAIResponsesStreamEvent struct {
	Type        string                     `json:"type"`
	Response    *openAIResponsesResponse   `json:"response,omitempty"`
	Delta       string                     `json:"delta,omitempty"`
	ItemID      string                     `json:"item_id,omitempty"`
	OutputIndex int                        `json:"output_index,omitempty"`
	Name        string                     `json:"name,omitempty"`
	Arguments   string                     `json:"arguments,omitempty"`
	Item        *openAIResponsesOutputItem `json:"item,omitempty"`
}

func contentToString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []byte:
		return string(t)
	default:
		b, err := json.Marshal(t)
		if err == nil {
			return string(b)
		}
		return fmt.Sprintf("%v", t)
	}
}

func responsesContentFromChatContent(content interface{}) interface{} {
	switch v := content.(type) {
	case nil:
		return []map[string]interface{}{}
	case string:
		if strings.TrimSpace(v) == "" {
			return []map[string]interface{}{}
		}
		return []map[string]interface{}{
			{
				"type": "input_text",
				"text": v,
			},
		}
	case []MessageContent:
		parts := make([]map[string]interface{}, 0, len(v))
		for _, part := range v {
			switch part.Type {
			case "text":
				if part.Text != "" {
					parts = append(parts, map[string]interface{}{
						"type": "input_text",
						"text": part.Text,
					})
				}
			case "image_url":
				if part.ImageURL != nil && part.ImageURL.URL != "" {
					parts = append(parts, map[string]interface{}{
						"type":      "input_image",
						"image_url": part.ImageURL.URL,
					})
				}
			}
		}
		if len(parts) > 0 {
			return parts
		}
		s := strings.TrimSpace(contentToString(content))
		if s == "" {
			return []map[string]interface{}{}
		}
		return []map[string]interface{}{{"type": "input_text", "text": s}}
	case []interface{}:
		parts := make([]map[string]interface{}, 0, len(v))
		for _, raw := range v {
			m, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}

			t, _ := m["type"].(string)
			switch t {
			case "text":
				if txt, ok := m["text"].(string); ok && txt != "" {
					parts = append(parts, map[string]interface{}{
						"type": "input_text",
						"text": txt,
					})
				}
			case "image_url":
				switch u := m["image_url"].(type) {
				case string:
					if u != "" {
						parts = append(parts, map[string]interface{}{
							"type":      "input_image",
							"image_url": u,
						})
					}
				case map[string]interface{}:
					if url, ok := u["url"].(string); ok && url != "" {
						parts = append(parts, map[string]interface{}{
							"type":      "input_image",
							"image_url": url,
						})
					}
				}
			case "input_text", "input_image":
				// already in Responses format
				if len(m) > 0 {
					parts = append(parts, m)
				}
			default:
				// best-effort: if it's a plain {text: "..."} object
				if txt, ok := m["text"].(string); ok && txt != "" {
					parts = append(parts, map[string]interface{}{
						"type": "input_text",
						"text": txt,
					})
				}
			}
		}
		if len(parts) > 0 {
			return parts
		}
		s := strings.TrimSpace(contentToString(content))
		if s == "" {
			return []map[string]interface{}{}
		}
		return []map[string]interface{}{{"type": "input_text", "text": s}}
	default:
		s := strings.TrimSpace(contentToString(content))
		if s == "" {
			return []map[string]interface{}{}
		}
		return []map[string]interface{}{{"type": "input_text", "text": s}}
	}
}

func (p *OpenAIProvider) buildResponsesInput(messages []ChatMessage) ([]interface{}, error) {
	input := make([]interface{}, 0, len(messages))

	isEmptyContent := func(v interface{}) bool {
		switch t := v.(type) {
		case nil:
			return true
		case string:
			return strings.TrimSpace(t) == ""
		default:
			return false
		}
	}

	for _, msg := range messages {
		switch msg.Role {
		case "tool":
			output := contentToString(msg.Content)
			input = append(input, map[string]interface{}{
				"type":    "function_call_output",
				"call_id": msg.ToolCallID,
				"output":  output,
			})
		case "assistant":
			if !isEmptyContent(msg.Content) {
				input = append(input, map[string]interface{}{
					"role":    "assistant",
					"content": responsesContentFromChatContent(msg.Content),
				})
			}
			for _, tc := range msg.ToolCalls {
				if tc.Function == nil {
					continue
				}
				input = append(input, map[string]interface{}{
					"type":      "function_call",
					"call_id":   tc.ID,
					"name":      tc.Function.Name,
					"arguments": tc.Function.Arguments,
				})
			}
		default:
			input = append(input, map[string]interface{}{
				"role":    msg.Role,
				"content": responsesContentFromChatContent(msg.Content),
			})
		}
	}

	return input, nil
}

func (p *OpenAIProvider) buildResponsesRequestBody(req *ChatCompletionRequest, stream bool) (map[string]interface{}, error) {
	// Prefer mapping OpenAI "system" messages to Responses API `instructions`
	// to maximize compatibility with the upstream schema.
	instructions := make([]string, 0, 2)
	filtered := make([]ChatMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		if m.Role == "system" {
			if s := strings.TrimSpace(contentToString(m.Content)); s != "" {
				instructions = append(instructions, s)
			}
			continue
		}
		filtered = append(filtered, m)
	}

	input, err := p.buildResponsesInput(filtered)
	if err != nil {
		return nil, err
	}

	body := map[string]interface{}{
		"model": req.Model,
		"input": input,
	}
	if len(instructions) > 0 {
		body["instructions"] = strings.Join(instructions, "\n")
	}

	if stream || req.Stream {
		body["stream"] = true
	}
	if req.Temperature != nil {
		body["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		body["top_p"] = *req.TopP
	}
	if req.MaxTokens != nil {
		body["max_output_tokens"] = *req.MaxTokens
	}
	if len(req.Tools) > 0 {
		body["tools"] = req.Tools
	}
	if req.ToolChoice != nil {
		body["tool_choice"] = req.ToolChoice
	}
	if req.ParallelToolCalls != nil {
		body["parallel_tool_calls"] = *req.ParallelToolCalls
	}

	// carry through unmodeled fields (request_params + client provided extras)
	// For Responses API, drop chat-completions-specific extras that may confuse some gateways.
	blockedExtras := map[string]struct{}{
		"stream_options": {},
		"messages":       {},
	}
	for k, v := range req.Extra {
		if _, blocked := blockedExtras[k]; blocked {
			continue
		}
		if _, exists := body[k]; exists {
			continue
		}
		body[k] = v
	}

	// Compatibility & privacy: default to not storing responses unless explicitly configured.
	if _, ok := body["store"]; !ok {
		body["store"] = false
	}

	return body, nil
}

func finishReasonFromResponses(resp *openAIResponsesResponse, sawToolCall bool) string {
	if resp != nil && resp.IncompleteDetails != nil {
		if strings.EqualFold(resp.IncompleteDetails.Reason, "max_output_tokens") {
			return "length"
		}
	}
	if sawToolCall {
		return "tool_calls"
	}
	return "stop"
}

func (p *OpenAIProvider) convertResponsesToChatCompletion(resp *openAIResponsesResponse) (*ChatCompletionResponse, error) {
	if resp == nil {
		return nil, fmt.Errorf("nil responses api response")
	}

	var contentBuilder strings.Builder
	toolCalls := make([]ToolCall, 0, 4)

	for _, item := range resp.Output {
		switch item.Type {
		case "message":
			if item.Role != "assistant" {
				continue
			}
			for _, part := range item.Content {
				if part.Text == "" {
					continue
				}
				// Common cases: output_text (Responses) or text (some compat layers)
				if part.Type == "output_text" || part.Type == "text" {
					contentBuilder.WriteString(part.Text)
				}
			}
		case "function_call":
			callID := item.CallID
			if callID == "" {
				callID = item.ID
			}
			toolCalls = append(toolCalls, ToolCall{
				ID:   callID,
				Type: "function",
				Function: &FunctionCall{
					Name:      item.Name,
					Arguments: item.Arguments,
				},
			})
		}
	}

	created := resp.CreatedAt
	if created == 0 {
		created = time.Now().Unix()
	}

	finishReason := finishReasonFromResponses(resp, len(toolCalls) > 0)
	standard := &ChatCompletionResponse{
		ID:      resp.ID,
		Object:  "chat.completion",
		Created: created,
		Model:   resp.Model,
		Choices: []ChatCompletionChoice{
			{
				Index: 0,
				Message: ChatCompletionMessage{
					Role:      "assistant",
					Content:   contentBuilder.String(),
					ToolCalls: toolCalls,
				},
				FinishReason: finishReason,
			},
		},
	}

	if resp.Usage != nil {
		standard.Usage = Usage{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		}
	}

	return standard, nil
}

func (p *OpenAIProvider) chatCompletionViaResponsesAPI(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	endpoint := joinURL(p.Config.BaseURL, "/responses")

	body, err := p.buildResponsesRequestBody(req, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build responses request: %w", err)
	}

	reqBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal responses request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.Config.APIKey)

	baseLower := ""
	if p.Config != nil {
		baseLower = strings.ToLower(p.Config.BaseURL)
	}
	isOfficial := strings.Contains(baseLower, "api.openai.com")

	// Some OpenAI-compatible gateways require an `x-api-key` header in addition to Authorization.
	hasXAPIKey := false
	for k := range p.Config.Headers {
		if strings.EqualFold(k, "x-api-key") {
			hasXAPIKey = true
			break
		}
	}
	if !hasXAPIKey && p.Config != nil && !strings.Contains(baseLower, "api.openai.com") {
		httpReq.Header.Set("x-api-key", p.Config.APIKey)
	}

	// Best-effort Cherry/OpenRouter-like headers for some gateways (won't override group headers).
	// NOTE: avoid guessing HTTP-Referer / X-Title values; those should be configured per group or forwarded from client.
	if !isOfficial {
		setHeaderIfMissing(httpReq, p.Config.Headers, "Accept", "*/*")
		setHeaderIfMissing(httpReq, p.Config.Headers, "Accept-Language", "zh-CN")
		setHeaderIfMissing(httpReq, p.Config.Headers, "Accept-Encoding", "identity")
		setHeaderIfMissing(httpReq, p.Config.Headers, "Priority", "u=1, i")
		// Default to TurnsAPI UA when missing (can be overridden by group headers or client-forwarded headers).
		setHeaderIfMissing(httpReq, p.Config.Headers, "User-Agent", "TurnsAPI/2.2.0")
		setHeaderIfMissing(httpReq, p.Config.Headers, "Sec-CH-UA", "\"Not=A?Brand\";v=\"24\", \"Chromium\";v=\"140\"")
		setHeaderIfMissing(httpReq, p.Config.Headers, "Sec-CH-UA-Mobile", "?0")
		setHeaderIfMissing(httpReq, p.Config.Headers, "Sec-CH-UA-Platform", "\"Windows\"")
		setHeaderIfMissing(httpReq, p.Config.Headers, "Sec-Fetch-Dest", "empty")
		setHeaderIfMissing(httpReq, p.Config.Headers, "Sec-Fetch-Mode", "cors")
		setHeaderIfMissing(httpReq, p.Config.Headers, "Sec-Fetch-Site", "cross-site")
		setHeaderIfMissing(httpReq, p.Config.Headers, "HTTP-Referer", "https://turnsapi.local")
		setHeaderIfMissing(httpReq, p.Config.Headers, "Referer", "https://turnsapi.local")
		setHeaderIfMissing(httpReq, p.Config.Headers, "Origin", "https://turnsapi.local")
		setHeaderIfMissing(httpReq, p.Config.Headers, "X-Title", "TurnsAPI")
	}

	for key, value := range p.Config.Headers {
		if !strings.EqualFold(key, "Authorization") {
			httpReq.Header.Set(key, value)
		}
	}

	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		log.Printf("OpenAI Responses request failed to send: endpoint=%s headers=%v body=%s err=%v",
			endpoint, sanitizeHeadersForLog(httpReq.Header), truncateForLog(reqBody, 2000), err)
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("OpenAI Responses request error: endpoint=%s status=%d headers=%v body=%s resp=%s",
			endpoint, resp.StatusCode, sanitizeHeadersForLog(httpReq.Header), truncateForLog(reqBody, 2000), truncateForLog(body, 2000))
		return nil, fmt.Errorf("openai responses %s failed: %w", endpoint, p.handleAPIError(resp.StatusCode, body))
	}

	var responsesResp openAIResponsesResponse
	if err := json.NewDecoder(resp.Body).Decode(&responsesResp); err != nil {
		return nil, fmt.Errorf("failed to decode responses api response: %w", err)
	}

	return p.convertResponsesToChatCompletion(&responsesResp)
}

func (p *OpenAIProvider) chatCompletionStreamViaResponsesAPI(ctx context.Context, req *ChatCompletionRequest, native bool) (<-chan StreamResponse, error) {
	body, err := p.buildResponsesRequestBody(req, true)
	if err != nil {
		return nil, fmt.Errorf("failed to build responses request: %w", err)
	}

	reqBodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal responses request: %w", err)
	}

	baseLower := ""
	if p.Config != nil {
		baseLower = strings.ToLower(p.Config.BaseURL)
	}

	candidatePaths := []string{"/responses"}
	// Compatibility: some OpenAI-compatible proxies expose streaming under a different path or require query-based routing.
	if !strings.Contains(baseLower, "api.openai.com") {
		candidatePaths = append(candidatePaths,
			"/responses/stream",
			"/stream/responses",
			"/responses?stream=true",
		)
	}

	isEndpointUnsupportedStatus := func(code int) bool {
		switch code {
		case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
			return true
		default:
			return false
		}
	}

	var resp *http.Response
	var lastErr error
	tried := make([]string, 0, len(candidatePaths))
	for i, pth := range candidatePaths {
		endpoint := joinURL(p.Config.BaseURL, pth)
		tried = append(tried, endpoint)

		httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBodyBytes))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Authorization", "Bearer "+p.Config.APIKey)
		httpReq.Header.Set("Cache-Control", "no-cache")

		// Some OpenAI-compatible gateways require an `x-api-key` header in addition to Authorization.
		hasXAPIKey := false
		for k := range p.Config.Headers {
			if strings.EqualFold(k, "x-api-key") {
				hasXAPIKey = true
				break
			}
		}
		if !hasXAPIKey && p.Config != nil && !strings.Contains(strings.ToLower(p.Config.BaseURL), "api.openai.com") {
			httpReq.Header.Set("x-api-key", p.Config.APIKey)
		}

		// Best-effort Cherry/OpenRouter-like headers for some gateways (won't override group headers).
		// NOTE: avoid guessing HTTP-Referer / X-Title values; those should be configured per group or forwarded from client.
		if !strings.Contains(baseLower, "api.openai.com") {
			setHeaderIfMissing(httpReq, p.Config.Headers, "Accept", "*/*")
			setHeaderIfMissing(httpReq, p.Config.Headers, "Accept-Language", "zh-CN")
			setHeaderIfMissing(httpReq, p.Config.Headers, "Accept-Encoding", "identity")
			setHeaderIfMissing(httpReq, p.Config.Headers, "Priority", "u=1, i")
			// Default to TurnsAPI UA when missing (can be overridden by group headers or client-forwarded headers).
			setHeaderIfMissing(httpReq, p.Config.Headers, "User-Agent", "TurnsAPI/2.2.0")
			setHeaderIfMissing(httpReq, p.Config.Headers, "Sec-CH-UA", "\"Not=A?Brand\";v=\"24\", \"Chromium\";v=\"140\"")
			setHeaderIfMissing(httpReq, p.Config.Headers, "Sec-CH-UA-Mobile", "?0")
			setHeaderIfMissing(httpReq, p.Config.Headers, "Sec-CH-UA-Platform", "\"Windows\"")
			setHeaderIfMissing(httpReq, p.Config.Headers, "Sec-Fetch-Dest", "empty")
			setHeaderIfMissing(httpReq, p.Config.Headers, "Sec-Fetch-Mode", "cors")
			setHeaderIfMissing(httpReq, p.Config.Headers, "Sec-Fetch-Site", "cross-site")
			setHeaderIfMissing(httpReq, p.Config.Headers, "HTTP-Referer", "https://turnsapi.local")
			setHeaderIfMissing(httpReq, p.Config.Headers, "Referer", "https://turnsapi.local")
			setHeaderIfMissing(httpReq, p.Config.Headers, "Origin", "https://turnsapi.local")
			setHeaderIfMissing(httpReq, p.Config.Headers, "X-Title", "TurnsAPI")
		}

		for key, value := range p.Config.Headers {
			if !strings.EqualFold(key, "Authorization") {
				httpReq.Header.Set(key, value)
			}
		}

		r, err := p.HTTPClient.Do(httpReq)
		if err != nil {
			log.Printf("OpenAI Responses stream failed to send: endpoint=%s headers=%v body=%s err=%v",
				endpoint, sanitizeHeadersForLog(httpReq.Header), truncateForLog(reqBodyBytes, 2000), err)
			return nil, fmt.Errorf("failed to send request: %w", err)
		}

		if r.StatusCode >= 200 && r.StatusCode < 300 {
			resp = r
			break
		}

		bodyBytes, _ := io.ReadAll(r.Body)
		r.Body.Close()
		log.Printf("OpenAI Responses stream error: endpoint=%s status=%d headers=%v body=%s resp=%s",
			endpoint, r.StatusCode, sanitizeHeadersForLog(httpReq.Header), truncateForLog(reqBodyBytes, 2000), truncateForLog(bodyBytes, 2000))
		apiErr := p.handleAPIError(r.StatusCode, bodyBytes)
		lastErr = fmt.Errorf("openai responses stream %s failed: %w", endpoint, apiErr)

		// If endpoint looks unsupported, try next compatibility path; otherwise fail fast.
		if isEndpointUnsupportedStatus(r.StatusCode) && i < len(candidatePaths)-1 {
			continue
		}
		return nil, lastErr
	}

	if resp == nil {
		if lastErr != nil {
			return nil, fmt.Errorf("openai responses stream failed (tried %d endpoints): %w", len(tried), lastErr)
		}
		return nil, fmt.Errorf("openai responses stream failed: no response")
	}

	streamChan := make(chan StreamResponse, 50)

	// Native: passthrough upstream SSE
	if native {
		go func() {
			defer close(streamChan)
			defer resp.Body.Close()

			scanner := bufio.NewScanner(resp.Body)
			scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
			for scanner.Scan() {
				line := scanner.Text()
				streamChan <- StreamResponse{Data: []byte(line + "\n"), Done: false}
			}
			if err := scanner.Err(); err != nil {
				streamChan <- StreamResponse{Error: err, Done: true}
				return
			}
			streamChan <- StreamResponse{Done: true}
		}()

		return streamChan, nil
	}

	// Standard: convert Responses streaming events into Chat Completions SSE chunks
	go func() {
		defer close(streamChan)
		defer resp.Body.Close()

		type fnInfo struct {
			CallID string
			Name   string
		}

		fnByItemID := make(map[string]fnInfo)
		var dataLines []string
		eventName := ""

		responseID := ""
		model := req.Model
		created := time.Now().Unix()
		sentRole := false
		sawToolCall := false
		completed := false

		emitChunk := func(delta map[string]interface{}, finishReason interface{}) {
			if responseID == "" {
				responseID = "chatcmpl_responses_proxy"
			}
			if model == "" {
				model = req.Model
			}

			chunk := map[string]interface{}{
				"id":      responseID,
				"object":  "chat.completion.chunk",
				"created": created,
				"model":   model,
				"choices": []map[string]interface{}{
					{
						"index":         0,
						"delta":         delta,
						"finish_reason": finishReason,
					},
				},
			}

			b, err := json.Marshal(chunk)
			if err != nil {
				streamChan <- StreamResponse{Error: err, Done: true}
				return
			}
			streamChan <- StreamResponse{Data: append(append([]byte("data: "), b...), []byte("\n\n")...), Done: false}
		}

		emitDone := func() {
			streamChan <- StreamResponse{Data: []byte("data: [DONE]\n\n"), Done: true}
		}

		flushEvent := func() bool {
			if len(dataLines) == 0 {
				eventName = ""
				return false
			}

			data := strings.Join(dataLines, "\n")
			dataLines = dataLines[:0]
			name := eventName
			eventName = ""

			if strings.TrimSpace(data) == "" {
				return false
			}
			if strings.TrimSpace(data) == "[DONE]" {
				emitDone()
				return true
			}

			var evt openAIResponsesStreamEvent
			if err := json.Unmarshal([]byte(data), &evt); err != nil {
				// Unknown payload; ignore to keep stream flowing.
				return false
			}

			evtType := evt.Type
			if evtType == "" {
				evtType = name
			}
			evtType = strings.TrimPrefix(evtType, "response.")

			switch evtType {
			case "created":
				if evt.Response != nil {
					responseID = evt.Response.ID
					if evt.Response.Model != "" {
						model = evt.Response.Model
					}
					if evt.Response.CreatedAt != 0 {
						created = evt.Response.CreatedAt
					}
				}
				if !sentRole {
					sentRole = true
					emitChunk(map[string]interface{}{"role": "assistant"}, nil)
				}

			case "output_text.delta":
				if !sentRole {
					sentRole = true
					emitChunk(map[string]interface{}{"role": "assistant"}, nil)
				}
				if evt.Delta != "" {
					emitChunk(map[string]interface{}{"content": evt.Delta}, nil)
				}

			case "output_item.added":
				if evt.Item != nil && evt.Item.Type == "function_call" {
					itemID := evt.Item.ID
					if itemID == "" {
						itemID = evt.ItemID
					}
					if itemID != "" {
						fnByItemID[itemID] = fnInfo{
							CallID: evt.Item.CallID,
							Name:   evt.Item.Name,
						}
					}
				}

			case "function_call_arguments.done":
				itemID := evt.ItemID
				info := fnByItemID[itemID]

				callID := info.CallID
				if callID == "" {
					callID = itemID
				}
				name := evt.Name
				if name == "" {
					name = info.Name
				}
				arguments := evt.Arguments
				if arguments == "" {
					arguments = "{}"
				}

				sawToolCall = true
				emitChunk(map[string]interface{}{
					"tool_calls": []map[string]interface{}{
						{
							"index": 0,
							"id":    callID,
							"type":  "function",
							"function": map[string]interface{}{
								"name":      name,
								"arguments": arguments,
							},
						},
					},
				}, nil)

			case "completed", "failed", "incomplete":
				if evt.Response != nil {
					if evt.Response.ID != "" {
						responseID = evt.Response.ID
					}
					if evt.Response.Model != "" {
						model = evt.Response.Model
					}
					if evt.Response.CreatedAt != 0 {
						created = evt.Response.CreatedAt
					}
				}

				finish := finishReasonFromResponses(evt.Response, sawToolCall)
				emitChunk(map[string]interface{}{}, finish)
				emitDone()
				completed = true
				return true
			}

			return false
		}

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

		for scanner.Scan() {
			line := scanner.Text()

			// SSE event boundary
			if line == "" {
				if flushEvent() {
					break
				}
				if completed {
					break
				}
				continue
			}

			if strings.HasPrefix(line, "event:") {
				eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
				continue
			}
			if strings.HasPrefix(line, "data:") {
				dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
				continue
			}
		}

		// Flush tail
		if !completed {
			flushEvent()
		}

		if err := scanner.Err(); err != nil {
			streamChan <- StreamResponse{Error: err, Done: true}
			return
		}

		if !completed {
			emitDone()
		}
	}()

	return streamChan, nil
}

func (p *OpenAIProvider) chatCompletionStreamFallbackNonStream(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// Fall back to non-stream Responses request and wrap it into a single-shot Chat Completions SSE stream.
	// This is useful when the upstream supports /responses but has flaky SSE proxying.
	nonStreamReq := *req
	nonStreamReq.Stream = false
	if nonStreamReq.Extra != nil {
		// Ensure stream isn't forced through unmodeled params.
		delete(nonStreamReq.Extra, "stream")
		delete(nonStreamReq.Extra, "stream_options")
	}

	resp, err := p.chatCompletionViaResponsesAPI(ctx, &nonStreamReq)
	if err != nil {
		return nil, err
	}
	if resp == nil || len(resp.Choices) == 0 {
		return nil, fmt.Errorf("responses fallback: empty response")
	}

	choice := resp.Choices[0]

	streamChan := make(chan StreamResponse, 10)
	go func() {
		defer close(streamChan)

		emit := func(delta map[string]interface{}, finishReason interface{}) bool {
			chunk := map[string]interface{}{
				"id":      resp.ID,
				"object":  "chat.completion.chunk",
				"created": resp.Created,
				"model":   resp.Model,
				"choices": []map[string]interface{}{
					{
						"index":         0,
						"delta":         delta,
						"finish_reason": finishReason,
					},
				},
			}

			b, mErr := json.Marshal(chunk)
			if mErr != nil {
				streamChan <- StreamResponse{Error: mErr, Done: true}
				return false
			}
			streamChan <- StreamResponse{Data: append(append([]byte("data: "), b...), []byte("\n\n")...), Done: false}
			return true
		}

		// role
		if !emit(map[string]interface{}{"role": "assistant"}, nil) {
			return
		}
		// content
		if strings.TrimSpace(choice.Message.Content) != "" {
			if !emit(map[string]interface{}{"content": choice.Message.Content}, nil) {
				return
			}
		}
		// tool calls
		if len(choice.Message.ToolCalls) > 0 {
			toolCalls := make([]map[string]interface{}, 0, len(choice.Message.ToolCalls))
			for i, tc := range choice.Message.ToolCalls {
				fn := map[string]interface{}{}
				if tc.Function != nil {
					fn["name"] = tc.Function.Name
					fn["arguments"] = tc.Function.Arguments
				}
				toolCalls = append(toolCalls, map[string]interface{}{
					"index":    i,
					"id":       tc.ID,
					"type":     tc.Type,
					"function": fn,
				})
			}
			if !emit(map[string]interface{}{"tool_calls": toolCalls}, nil) {
				return
			}
		}

		// finish
		if !emit(map[string]interface{}{}, choice.FinishReason) {
			return
		}
		streamChan <- StreamResponse{Data: []byte("data: [DONE]\n\n"), Done: true}
	}()

	return streamChan, nil
}

func (p *OpenAIProvider) chatCompletionViaChatCompletionsAPI(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	endpoint := joinURL(p.Config.BaseURL, "/chat/completions")

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.Config.APIKey)

	for key, value := range p.Config.Headers {
		if key != "Authorization" {
			httpReq.Header.Set(key, value)
		}
	}

	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("openai chat completions %s failed: %w", endpoint, p.handleAPIError(resp.StatusCode, body))
	}

	var response ChatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response, nil
}

func (p *OpenAIProvider) chatCompletionStreamViaChatCompletionsAPI(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// 确保设置stream为true
	req.Stream = true

	endpoint := joinURL(p.Config.BaseURL, "/chat/completions")

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.Config.APIKey)
	httpReq.Header.Set("Accept", "text/event-stream")
	httpReq.Header.Set("Cache-Control", "no-cache")

	for key, value := range p.Config.Headers {
		if key != "Authorization" {
			httpReq.Header.Set(key, value)
		}
	}

	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("openai chat completions stream %s failed: %w", endpoint, p.handleAPIError(resp.StatusCode, body))
	}

	streamChan := make(chan StreamResponse, 10)

	go func() {
		defer close(streamChan)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()

			streamChan <- StreamResponse{
				Data: []byte(line + "\n"),
				Done: false,
			}

			if strings.Contains(line, "[DONE]") {
				streamChan <- StreamResponse{Done: true}
				return
			}
		}

		if err := scanner.Err(); err != nil {
			streamChan <- StreamResponse{Error: err, Done: true}
		}
	}()

	return streamChan, nil
}

// ChatCompletion 发送聊天完成请求
func (p *OpenAIProvider) ChatCompletion(ctx context.Context, req *ChatCompletionRequest) (*ChatCompletionResponse, error) {
	// 验证工具调用相关参数
	if err := p.validateToolCallRequest(req); err != nil {
		return nil, fmt.Errorf("tool call validation failed: %w", err)
	}

	if p.useResponsesAPI() {
		return p.chatCompletionViaResponsesAPI(ctx, req)
	}

	return p.chatCompletionViaChatCompletionsAPI(ctx, req)
}

// ChatCompletionStream 发送流式聊天完成请求
func (p *OpenAIProvider) ChatCompletionStream(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// 验证工具调用相关参数
	if err := p.validateToolCallRequest(req); err != nil {
		return nil, fmt.Errorf("tool call validation failed: %w", err)
	}

	// 确保设置stream为true
	req.Stream = true

	if p.useResponsesAPI() {
		ch, err := p.chatCompletionStreamViaResponsesAPI(ctx, req, false)
		if err == nil {
			return ch, nil
		}
		var tce *ToolCallError
		if errors.As(err, &tce) && tce != nil && tce.Type == "server_error" {
			return p.chatCompletionStreamFallbackNonStream(ctx, req)
		}
		return nil, err
	}

	return p.chatCompletionStreamViaChatCompletionsAPI(ctx, req)
}

// ChatCompletionStreamNative 发送原生格式流式聊天完成请求
func (p *OpenAIProvider) ChatCompletionStreamNative(ctx context.Context, req *ChatCompletionRequest) (<-chan StreamResponse, error) {
	// 对于 Responses API，原生流式即转发 /v1/responses 的 SSE 事件
	if p.useResponsesAPI() {
		// 确保设置stream为true
		req.Stream = true
		return p.chatCompletionStreamViaResponsesAPI(ctx, req, true)
	}

	// OpenAI Chat Completions 的原生流与标准流一致
	return p.ChatCompletionStream(ctx, req)
}

// GetModels 获取可用模型列表
func (p *OpenAIProvider) GetModels(ctx context.Context) (interface{}, error) {
	endpoint := joinURL(p.Config.BaseURL, "/models")

	httpReq, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.Config.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")

	// 添加自定义头
	for key, value := range p.Config.Headers {
		httpReq.Header.Set(key, value)
	}

	resp, err := p.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, p.handleAPIError(resp.StatusCode, body)
	}

	var models interface{}
	if err := json.NewDecoder(resp.Body).Decode(&models); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return models, nil
}

// HealthCheck 健康检查
func (p *OpenAIProvider) HealthCheck(ctx context.Context) error {
	// 创建一个简单的健康检查请求，只检查连接性
	req, err := http.NewRequestWithContext(ctx, "GET", joinURL(p.Config.BaseURL, "/models"), nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	// 添加认证头
	req.Header.Set("Authorization", "Bearer "+p.Config.APIKey)
	req.Header.Set("Content-Type", "application/json")

	// 添加自定义头
	for key, value := range p.Config.Headers {
		req.Header.Set(key, value)
	}

	// 发送请求
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send health check request: %w", err)
	}
	defer resp.Body.Close()

	// 只要返回状态码是 2xx 就认为健康
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	// 如果状态码不是 2xx，读取错误信息
	body, _ := io.ReadAll(resp.Body)
	return p.handleAPIError(resp.StatusCode, body)
}

// TransformRequest OpenAI格式不需要转换
func (p *OpenAIProvider) TransformRequest(req *ChatCompletionRequest) (interface{}, error) {
	return req, nil
}

// TransformResponse OpenAI格式不需要转换
func (p *OpenAIProvider) TransformResponse(resp interface{}) (*ChatCompletionResponse, error) {
	if response, ok := resp.(*ChatCompletionResponse); ok {
		return response, nil
	}
	return nil, fmt.Errorf("invalid response type")
}

// CreateHTTPRequest 创建HTTP请求
func (p *OpenAIProvider) CreateHTTPRequest(ctx context.Context, endpoint string, body interface{}) (*http.Request, error) {
	var bodyReader io.Reader

	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal body: %w", err)
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.Config.APIKey)

	for key, value := range p.Config.Headers {
		if key != "Authorization" {
			req.Header.Set(key, value)
		}
	}

	return req, nil
}

// ParseHTTPResponse 解析HTTP响应
func (p *OpenAIProvider) ParseHTTPResponse(resp *http.Response) (interface{}, error) {
	var response ChatCompletionResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &response, nil
}

// validateToolCallRequest 验证工具调用请求参数
func (p *OpenAIProvider) validateToolCallRequest(req *ChatCompletionRequest) error {
	// 验证消息序列中的工具调用逻辑
	if err := p.validateMessageSequence(req.Messages); err != nil {
		return err
	}

	// 如果没有工具定义，无需验证工具相关参数
	if len(req.Tools) == 0 {
		return nil
	}

	// 验证工具数量限制
	if len(req.Tools) > 128 {
		return &ToolCallError{
			Type:    "validation_error",
			Code:    "too_many_tools",
			Message: fmt.Sprintf("too many tools provided: %d, maximum allowed is 128", len(req.Tools)),
		}
	}

	// 验证工具定义
	toolNames := make(map[string]bool)
	for i, tool := range req.Tools {
		if tool.Type != "function" {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "invalid_tool_type",
				Message: fmt.Sprintf("tool[%d]: unsupported tool type '%s', only 'function' is supported", i, tool.Type),
			}
		}

		if tool.Function == nil {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "missing_function_definition",
				Message: fmt.Sprintf("tool[%d]: function definition is required", i),
			}
		}

		if tool.Function.Name == "" {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "missing_function_name",
				Message: fmt.Sprintf("tool[%d]: function name is required", i),
			}
		}

		// 验证函数名称格式
		if !isValidFunctionName(tool.Function.Name) {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "invalid_function_name",
				Message: fmt.Sprintf("tool[%d]: function name '%s' is invalid, must contain only letters, numbers, underscores, and hyphens, and be 1-64 characters long", i, tool.Function.Name),
			}
		}

		// 检查函数名称重复
		if toolNames[tool.Function.Name] {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "duplicate_function_name",
				Message: fmt.Sprintf("tool[%d]: duplicate function name '%s'", i, tool.Function.Name),
			}
		}
		toolNames[tool.Function.Name] = true

		// 函数描述长度不设限制，允许用户自由定义

		// 验证参数schema
		if err := p.validateFunctionParameters(tool.Function, i); err != nil {
			return err
		}
	}

	// 验证tool_choice参数
	if req.ToolChoice != nil {
		if err := p.validateToolChoice(req.ToolChoice, toolNames); err != nil {
			return err
		}
	}

	// 验证parallel_tool_calls参数
	if req.ParallelToolCalls != nil && len(req.Tools) == 1 {
		// 如果只有一个工具，parallel_tool_calls应该为false或nil
		if *req.ParallelToolCalls {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "invalid_parallel_tool_calls",
				Message: "parallel_tool_calls cannot be true when only one tool is provided",
			}
		}
	}

	return nil
}

// validateFunctionParameters 验证函数参数schema
func (p *OpenAIProvider) validateFunctionParameters(function *Function, toolIndex int) error {
	if function.Parameters == nil {
		return nil
	}

	// 验证parameters是否为有效的JSON Schema
	parametersBytes, err := json.Marshal(function.Parameters)
	if err != nil {
		return &ToolCallError{
			Type:    "validation_error",
			Code:    "invalid_parameters_schema",
			Message: fmt.Sprintf("tool[%d]: function parameters must be valid JSON: %v", toolIndex, err),
		}
	}

	// 验证参数schema大小
	if len(parametersBytes) > 100*1024 { // 100KB limit
		return &ToolCallError{
			Type:    "validation_error",
			Code:    "parameters_schema_too_large",
			Message: fmt.Sprintf("tool[%d]: function parameters schema is too large (%d bytes), maximum allowed is 100KB", toolIndex, len(parametersBytes)),
		}
	}

	return nil
}

// validateToolChoice 验证tool_choice参数
func (p *OpenAIProvider) validateToolChoice(toolChoice interface{}, availableTools map[string]bool) error {
	switch choice := toolChoice.(type) {
	case string:
		// 验证字符串类型的tool_choice
		validChoices := []string{"none", "auto", "required"}
		valid := false
		for _, validChoice := range validChoices {
			if choice == validChoice {
				valid = true
				break
			}
		}
		if !valid {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "invalid_tool_choice",
				Message: fmt.Sprintf("invalid tool_choice string: '%s', must be one of: none, auto, required", choice),
			}
		}
	case map[string]interface{}:
		// 验证对象类型的tool_choice
		if toolType, ok := choice["type"].(string); !ok || toolType != "function" {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "invalid_tool_choice_type",
				Message: "tool_choice object must have type 'function'",
			}
		}

		if function, ok := choice["function"].(map[string]interface{}); ok {
			if name, ok := function["name"].(string); !ok || name == "" {
				return &ToolCallError{
					Type:    "validation_error",
					Code:    "missing_tool_choice_function_name",
					Message: "tool_choice function must have a valid name",
				}
			} else {
				// 验证指定的函数是否存在
				if !availableTools[name] {
					return &ToolCallError{
						Type:    "validation_error",
						Code:    "unknown_tool_choice_function",
						Message: fmt.Sprintf("tool_choice function '%s' is not defined in tools", name),
					}
				}
			}
		} else {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "missing_tool_choice_function",
				Message: "tool_choice object must have a function field",
			}
		}
	case ToolChoiceFunction:
		// 验证结构体类型的tool_choice
		if choice.Type != "function" {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "invalid_tool_choice_type",
				Message: "tool_choice type must be 'function'",
			}
		}
		if choice.Function == nil || choice.Function.Name == "" {
			return &ToolCallError{
				Type:    "validation_error",
				Code:    "missing_tool_choice_function_name",
				Message: "tool_choice function must have a valid name",
			}
		} else {
			// 验证指定的函数是否存在
			if !availableTools[choice.Function.Name] {
				return &ToolCallError{
					Type:    "validation_error",
					Code:    "unknown_tool_choice_function",
					Message: fmt.Sprintf("tool_choice function '%s' is not defined in tools", choice.Function.Name),
				}
			}
		}
	default:
		return &ToolCallError{
			Type:    "validation_error",
			Code:    "invalid_tool_choice_type",
			Message: fmt.Sprintf("invalid tool_choice type: %T", choice),
		}
	}

	return nil
}

// isValidFunctionName 验证函数名称格式
func isValidFunctionName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}

	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}

	return true
}

// handleAPIError 处理API错误响应
func (p *OpenAIProvider) handleAPIError(statusCode int, body []byte) error {
	// 尝试解析OpenAI错误格式
	var apiError struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}

	if err := json.Unmarshal(body, &apiError); err == nil && apiError.Error.Message != "" {
		// 根据错误类型返回相应的ToolCallError
		switch apiError.Error.Type {
		case "invalid_request_error":
			// 检查是否是工具调用相关的错误
			if strings.Contains(apiError.Error.Message, "tool") ||
				strings.Contains(apiError.Error.Message, "function") {
				return &ToolCallError{
					Type:    "tool_call_error",
					Code:    apiError.Error.Code,
					Message: apiError.Error.Message,
				}
			}
			return &ToolCallError{
				Type:    "validation_error",
				Code:    apiError.Error.Code,
				Message: apiError.Error.Message,
			}
		case "rate_limit_exceeded":
			return &ToolCallError{
				Type:    "rate_limit_error",
				Code:    "rate_limit_exceeded",
				Message: apiError.Error.Message,
			}
		case "insufficient_quota":
			return &ToolCallError{
				Type:    "quota_error",
				Code:    "insufficient_quota",
				Message: apiError.Error.Message,
			}
		case "server_error":
			return &ToolCallError{
				Type:    "server_error",
				Code:    "internal_server_error",
				Message: apiError.Error.Message,
			}
		case "authentication_error":
			return &ToolCallError{
				Type:    "authentication_error",
				Code:    "unauthorized",
				Message: apiError.Error.Message,
			}
		default:
			return &ToolCallError{
				Type:    "api_error",
				Code:    apiError.Error.Code,
				Message: apiError.Error.Message,
			}
		}
	}

	// 如果无法解析错误格式，根据状态码返回通用错误
	switch statusCode {
	case 400:
		return &ToolCallError{
			Type:    "validation_error",
			Code:    "bad_request",
			Message: fmt.Sprintf("Bad request: %s", string(body)),
		}
	case 401:
		return &ToolCallError{
			Type:    "authentication_error",
			Code:    "unauthorized",
			Message: "Invalid API key or authentication failed",
		}
	case 403:
		return &ToolCallError{
			Type:    "permission_error",
			Code:    "forbidden",
			Message: "Access forbidden - insufficient permissions",
		}
	case 404:
		return &ToolCallError{
			Type:    "not_found_error",
			Code:    "not_found",
			Message: "The requested resource was not found",
		}
	case 429:
		return &ToolCallError{
			Type:    "rate_limit_error",
			Code:    "rate_limit_exceeded",
			Message: "Rate limit exceeded - please try again later",
		}
	case 500, 502, 503, 504:
		bodyStr := strings.TrimSpace(string(body))
		// 检测是否为HTML响应（如Cloudflare错误页面）
		if strings.Contains(bodyStr, "<!DOCTYPE") || strings.Contains(bodyStr, "<html") || strings.Contains(bodyStr, "<HTML") {
			// 尝试从HTML中提取标题作为错误信息
			titleStart := strings.Index(bodyStr, "<title>")
			titleEnd := strings.Index(bodyStr, "</title>")
			if titleStart != -1 && titleEnd != -1 && titleEnd > titleStart {
				title := bodyStr[titleStart+7 : titleEnd]
				bodyStr = fmt.Sprintf("HTML error page: %s", strings.TrimSpace(title))
			} else {
				bodyStr = "HTML error page received (likely CDN/proxy error)"
			}
		} else if len(bodyStr) > 200 {
			bodyStr = bodyStr[:200] + "..."
		}
		if bodyStr != "" {
			bodyStr = " - " + bodyStr
		}
		return &ToolCallError{
			Type:    "server_error",
			Code:    "internal_server_error",
			Message: fmt.Sprintf("Server error (status %d) - please try again later%s", statusCode, bodyStr),
		}
	default:
		return &ToolCallError{
			Type:    "api_error",
			Code:    "unknown_error",
			Message: fmt.Sprintf("API request failed with status %d: %s", statusCode, string(body)),
		}
	}
}

// validateMessageSequence 验证消息序列中的工具调用逻辑
func (p *OpenAIProvider) validateMessageSequence(messages []ChatMessage) error {
	for i, msg := range messages {
		switch msg.Role {
		case "tool":
			// tool消息必须跟在带有tool_calls的assistant消息后面（可能中间有其他tool消息）
			if i == 0 {
				return &ToolCallError{
					Type:    "validation_error",
					Code:    "invalid_message_sequence",
					Message: "messages with role \"tool\" must be a response to a preceding message with \"tool_calls\"",
				}
			}

			// 向前查找最近的assistant消息
			var assistantMsg *ChatMessage
			for j := i - 1; j >= 0; j-- {
				if messages[j].Role == "assistant" {
					assistantMsg = &messages[j]
					break
				} else if messages[j].Role != "tool" {
					// 如果遇到非tool、非assistant的消息，停止查找
					break
				}
			}

			// 检查是否找到了assistant消息且包含tool_calls
			if assistantMsg == nil || len(assistantMsg.ToolCalls) == 0 {
				return &ToolCallError{
					Type:    "validation_error",
					Code:    "invalid_message_sequence",
					Message: "messages with role \"tool\" must be a response to a preceding message with \"tool_calls\"",
				}
			}

			// 验证tool消息必须有tool_call_id
			if msg.ToolCallID == "" {
				return &ToolCallError{
					Type:    "validation_error",
					Code:    "missing_tool_call_id",
					Message: "messages with role \"tool\" must have a \"tool_call_id\"",
				}
			}

			// 验证tool_call_id是否对应前面的tool_calls
			validToolCallID := false
			for _, toolCall := range assistantMsg.ToolCalls {
				if toolCall.ID == msg.ToolCallID {
					validToolCallID = true
					break
				}
			}
			if !validToolCallID {
				return &ToolCallError{
					Type:    "validation_error",
					Code:    "invalid_tool_call_id",
					Message: fmt.Sprintf("tool_call_id \"%s\" does not match any tool_calls in the preceding assistant message", msg.ToolCallID),
				}
			}

		case "assistant":
			// 如果assistant消息包含tool_calls，验证其格式
			if len(msg.ToolCalls) > 0 {
				for j, toolCall := range msg.ToolCalls {
					if toolCall.ID == "" {
						return &ToolCallError{
							Type:    "validation_error",
							Code:    "missing_tool_call_id",
							Message: fmt.Sprintf("tool_calls[%d] must have an \"id\"", j),
						}
					}

					if toolCall.Type != "function" {
						return &ToolCallError{
							Type:    "validation_error",
							Code:    "invalid_tool_call_type",
							Message: fmt.Sprintf("tool_calls[%d] type must be \"function\"", j),
						}
					}

					if toolCall.Function == nil {
						return &ToolCallError{
							Type:    "validation_error",
							Code:    "missing_function_call",
							Message: fmt.Sprintf("tool_calls[%d] must have a \"function\"", j),
						}
					}

					if toolCall.Function.Name == "" {
						return &ToolCallError{
							Type:    "validation_error",
							Code:    "missing_function_name",
							Message: fmt.Sprintf("tool_calls[%d].function must have a \"name\"", j),
						}
					}
				}
			}
		}
	}

	return nil
}
