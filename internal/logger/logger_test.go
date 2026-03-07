package logger

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExtractToolCallInfo 测试工具调用信息提取
func TestExtractToolCallInfo(t *testing.T) {
	// 创建临时数据库用于测试
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	logger, err := NewRequestLogger(dbPath)
	if err != nil {
		t.Fatalf("Failed to create request logger: %v", err)
	}
	defer logger.Close()

	tests := []struct {
		name            string
		requestBody     string
		responseBody    string
		expectHasTools  bool
		expectCount     int
		expectToolNames string
	}{
		{
			name: "request with tools definition",
			requestBody: `{
				"model": "gpt-3.5-turbo",
				"messages": [{"role": "user", "content": "What's the weather?"}],
				"tools": [
					{
						"type": "function",
						"function": {
							"name": "get_weather",
							"description": "Get current weather"
						}
					},
					{
						"type": "function",
						"function": {
							"name": "get_forecast",
							"description": "Get weather forecast"
						}
					}
				]
			}`,
			responseBody: `{
				"choices": [{
					"message": {
						"role": "assistant",
						"content": "",
						"tool_calls": [
							{
								"id": "call_123",
								"type": "function",
								"function": {
									"name": "get_weather",
									"arguments": "{\"location\": \"New York\"}"
								}
							}
						]
					}
				}]
			}`,
			expectHasTools:  true,
			expectCount:     1,
			expectToolNames: "get_weather,get_forecast",
		},
		{
			name: "streaming response with tool calls",
			requestBody: `{
				"model": "gpt-3.5-turbo",
				"messages": [{"role": "user", "content": "Help me"}],
				"tools": [
					{
						"type": "function",
						"function": {
							"name": "help_function",
							"description": "Provide help"
						}
					}
				],
				"stream": true
			}`,
			responseBody: `data: {"choices": [{"delta": {"tool_calls": [{"id": "call_456", "type": "function", "function": {"name": "help_function", "arguments": "{\"query\": \"help\"}"}}]}}]}

data: [DONE]`,
			expectHasTools:  true,
			expectCount:     1,
			expectToolNames: "help_function",
		},
		{
			name: "multiple tool calls in response",
			requestBody: `{
				"model": "gpt-3.5-turbo",
				"messages": [{"role": "user", "content": "Get weather and forecast"}],
				"tools": [
					{
						"type": "function",
						"function": {
							"name": "get_weather",
							"description": "Get current weather"
						}
					},
					{
						"type": "function",
						"function": {
							"name": "get_forecast",
							"description": "Get weather forecast"
						}
					}
				]
			}`,
			responseBody: `{
				"choices": [{
					"message": {
						"role": "assistant",
						"content": "",
						"tool_calls": [
							{
								"id": "call_123",
								"type": "function",
								"function": {
									"name": "get_weather",
									"arguments": "{\"location\": \"New York\"}"
								}
							},
							{
								"id": "call_456",
								"type": "function",
								"function": {
									"name": "get_forecast",
									"arguments": "{\"location\": \"New York\", \"days\": 3}"
								}
							}
						]
					}
				}]
			}`,
			expectHasTools:  true,
			expectCount:     2,
			expectToolNames: "get_weather,get_forecast",
		},
		{
			name: "no tools in request or response",
			requestBody: `{
				"model": "gpt-3.5-turbo",
				"messages": [{"role": "user", "content": "Hello"}]
			}`,
			responseBody: `{
				"choices": [{
					"message": {
						"role": "assistant",
						"content": "Hello! How can I help you today?"
					}
				}]
			}`,
			expectHasTools:  false,
			expectCount:     0,
			expectToolNames: "",
		},
		{
			name: "tools defined but not called",
			requestBody: `{
				"model": "gpt-3.5-turbo",
				"messages": [{"role": "user", "content": "Just say hello"}],
				"tools": [
					{
						"type": "function",
						"function": {
							"name": "get_weather",
							"description": "Get current weather"
						}
					}
				]
			}`,
			responseBody: `{
				"choices": [{
					"message": {
						"role": "assistant",
						"content": "Hello! How can I help you today?"
					}
				}]
			}`,
			expectHasTools:  true,
			expectCount:     0,
			expectToolNames: "get_weather",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasTools, count, toolNames := logger.extractToolCallInfo(tt.requestBody, tt.responseBody)

			if hasTools != tt.expectHasTools {
				t.Errorf("Expected hasTools %v, got %v", tt.expectHasTools, hasTools)
			}

			if count != tt.expectCount {
				t.Errorf("Expected count %d, got %d", tt.expectCount, count)
			}

			if toolNames != tt.expectToolNames {
				t.Errorf("Expected toolNames '%s', got '%s'", tt.expectToolNames, toolNames)
			}
		})
	}
}

// TestLogRequestWithToolCalls 测试带工具调用的请求日志记录
func TestLogRequestWithToolCalls(t *testing.T) {
	// 创建临时数据库用于测试
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	logger, err := NewRequestLogger(dbPath)
	if err != nil {
		t.Fatalf("Failed to create request logger: %v", err)
	}
	defer logger.Close()

	// 记录一个带工具调用的请求
	requestBody := `{
		"model": "gpt-3.5-turbo",
		"messages": [{"role": "user", "content": "What's the weather?"}],
		"tools": [
			{
				"type": "function",
				"function": {
					"name": "get_weather",
					"description": "Get current weather"
				}
			}
		]
	}`

	responseBody := `{
		"choices": [{
			"message": {
				"role": "assistant",
				"content": "",
				"tool_calls": [
					{
						"id": "call_123",
						"type": "function",
						"function": {
							"name": "get_weather",
							"arguments": "{\"location\": \"New York\"}"
						}
					}
				]
			}
		}],
		"usage": {
			"total_tokens": 50
		}
	}`

	logger.LogRequest(
		"test-key", "test-key-id", "test-group", "test-openrouter-key",
		"gpt-3.5-turbo", requestBody, responseBody, "127.0.0.1",
		200, false, time.Millisecond*100, nil,
	)

	// 验证日志是否正确记录
	logs, err := logger.GetRequestLogs("test-key", "", 10, 0)
	if err != nil {
		t.Fatalf("Failed to get request logs: %v", err)
	}

	if len(logs) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(logs))
	}

	log := logs[0]
	if !log.HasToolCalls {
		t.Error("Expected HasToolCalls to be true")
	}

	if log.ToolCallsCount != 1 {
		t.Errorf("Expected ToolCallsCount 1, got %d", log.ToolCallsCount)
	}

	if log.ToolNames != "get_weather" {
		t.Errorf("Expected ToolNames 'get_weather', got '%s'", log.ToolNames)
	}

	if log.TokensUsed != 50 {
		t.Errorf("Expected TokensUsed 50, got %d", log.TokensUsed)
	}
}

// TestExtractToolCallsFromStream 测试从流式响应中提取工具调用
func TestExtractToolCallsFromStream(t *testing.T) {
	// 创建临时数据库用于测试
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	logger, err := NewRequestLogger(dbPath)
	if err != nil {
		t.Fatalf("Failed to create request logger: %v", err)
	}
	defer logger.Close()

	tests := []struct {
		name        string
		streamBody  string
		expectCount int
		expectNames []string
	}{
		{
			name: "single tool call in stream",
			streamBody: `data: {"choices": [{"delta": {"tool_calls": [{"id": "call_123", "type": "function", "function": {"name": "get_weather", "arguments": "{\"location\": \"NY\"}"}}]}}]}

data: [DONE]`,
			expectCount: 1,
			expectNames: []string{"get_weather"},
		},
		{
			name: "multiple tool calls in stream",
			streamBody: `data: {"choices": [{"delta": {"tool_calls": [{"id": "call_123", "type": "function", "function": {"name": "get_weather"}}]}}]}

data: {"choices": [{"delta": {"tool_calls": [{"id": "call_456", "type": "function", "function": {"name": "get_forecast"}}]}}]}

data: [DONE]`,
			expectCount: 2,
			expectNames: []string{"get_weather", "get_forecast"},
		},
		{
			name: "no tool calls in stream",
			streamBody: `data: {"choices": [{"delta": {"content": "Hello"}}]}

data: {"choices": [{"delta": {"content": " world"}}]}

data: [DONE]`,
			expectCount: 0,
			expectNames: []string{},
		},
		{
			name: "tool calls with processing messages",
			streamBody: `data: OPENROUTER PROCESSING

data: {"choices": [{"delta": {"tool_calls": [{"id": "call_123", "type": "function", "function": {"name": "test_function"}}]}}]}

data: PROCESSING

data: [DONE]`,
			expectCount: 1,
			expectNames: []string{"test_function"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var toolNames []string
			count := logger.extractToolCallsFromStream(tt.streamBody, &toolNames)

			if count != tt.expectCount {
				t.Errorf("Expected count %d, got %d", tt.expectCount, count)
			}

			if len(toolNames) != len(tt.expectNames) {
				t.Errorf("Expected %d tool names, got %d", len(tt.expectNames), len(toolNames))
			}

			for i, expectedName := range tt.expectNames {
				if i >= len(toolNames) || toolNames[i] != expectedName {
					t.Errorf("Expected tool name[%d] '%s', got '%s'", i, expectedName, toolNames[i])
				}
			}
		})
	}
}

// TestDatabaseToolCallFields 测试数据库工具调用字段
func TestDatabaseToolCallFields(t *testing.T) {
	// 创建临时数据库用于测试
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// 创建测试日志记录
	log := &RequestLog{
		ProxyKeyName:    "test-key",
		ProxyKeyID:      "test-key-id",
		ProviderGroup:   "test-group",
		OpenRouterKey:   "test-openrouter-key",
		Model:           "gpt-3.5-turbo",
		RequestBody:     `{"model": "gpt-3.5-turbo", "messages": []}`,
		ResponseBody:    `{"choices": []}`,
		StatusCode:      200,
		IsStream:        false,
		Duration:        100,
		TokensUsed:      50,
		TokensEstimated: false,
		ClientIP:        "127.0.0.1",
		CreatedAt:       time.Now(),
		HasToolCalls:    true,
		ToolCallsCount:  2,
		ToolNames:       "get_weather,get_forecast",
	}

	// 插入日志记录
	err = db.InsertRequestLog(log)
	if err != nil {
		t.Fatalf("Failed to insert request log: %v", err)
	}

	// 验证记录是否正确插入
	retrievedLog, err := db.GetRequestLogDetail(log.ID)
	if err != nil {
		t.Fatalf("Failed to get request log detail: %v", err)
	}

	if !retrievedLog.HasToolCalls {
		t.Error("Expected HasToolCalls to be true")
	}

	if retrievedLog.ToolCallsCount != 2 {
		t.Errorf("Expected ToolCallsCount 2, got %d", retrievedLog.ToolCallsCount)
	}

	if retrievedLog.ToolNames != "get_weather,get_forecast" {
		t.Errorf("Expected ToolNames 'get_weather,get_forecast', got '%s'", retrievedLog.ToolNames)
	}
}

// TestRequestLogSummaryWithToolCalls 测试带工具调用的请求日志摘要
func TestRequestLogSummaryWithToolCalls(t *testing.T) {
	// 创建临时数据库用于测试
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	logger, err := NewRequestLogger(dbPath)
	if err != nil {
		t.Fatalf("Failed to create request logger: %v", err)
	}
	defer logger.Close()

	// 记录多个请求，有些带工具调用，有些不带
	testCases := []struct {
		hasTools   bool
		toolsCount int
		toolNames  string
	}{
		{true, 1, "get_weather"},
		{true, 2, "get_weather,get_forecast"},
		{false, 0, ""},
		{true, 1, "calculate"},
	}

	for _, tc := range testCases {
		requestBody := `{"model": "gpt-3.5-turbo", "messages": []}`
		responseBody := `{"choices": []}`

		if tc.hasTools {
			toolNames := strings.Split(tc.toolNames, ",")
			toolsParts := make([]string, 0, tc.toolsCount)
			toolCallsParts := make([]string, 0, tc.toolsCount)
			for i := 0; i < tc.toolsCount; i++ {
				name := fmt.Sprintf("tool_%d", i)
				if i < len(toolNames) && toolNames[i] != "" {
					name = toolNames[i]
				}
				toolsParts = append(
					toolsParts,
					fmt.Sprintf(`{"type":"function","function":{"name":"%s"}}`, name),
				)
				toolCallsParts = append(
					toolCallsParts,
					fmt.Sprintf(
						`{"id":"call_%d","type":"function","function":{"name":"%s","arguments":"{}"}}`,
						i,
						name,
					),
				)
			}
			requestBody = fmt.Sprintf(
				`{"model":"gpt-3.5-turbo","messages":[],"tools":[%s]}`,
				strings.Join(toolsParts, ","),
			)
			responseBody = fmt.Sprintf(
				`{"choices":[{"message":{"role":"assistant","content":"","tool_calls":[%s]}}]}`,
				strings.Join(toolCallsParts, ","),
			)
		}

		logger.LogRequest(
			"test-key", "test-key-id", "test-group", "test-openrouter-key",
			"gpt-3.5-turbo", requestBody, responseBody, "127.0.0.1",
			200, false, time.Millisecond*100, nil,
		)
	}

	// 获取日志摘要
	logs, err := logger.GetRequestLogs("test-key", "", 10, 0)
	if err != nil {
		t.Fatalf("Failed to get request logs: %v", err)
	}

	if len(logs) != len(testCases) {
		t.Fatalf("Expected %d log entries, got %d", len(testCases), len(logs))
	}

	// 验证每个日志记录的工具调用信息
	for idx, log := range logs {
		// 注意：日志是按创建时间倒序返回的，所以需要反向索引
		expectedIndex := len(testCases) - 1 - idx
		expected := testCases[expectedIndex]

		if log.HasToolCalls != expected.hasTools {
			t.Errorf("Log %d: Expected HasToolCalls %v, got %v", idx, expected.hasTools, log.HasToolCalls)
		}

		if log.ToolCallsCount != expected.toolsCount {
			t.Errorf("Log %d: Expected ToolCallsCount %d, got %d", idx, expected.toolsCount, log.ToolCallsCount)
		}

		if log.ToolNames != expected.toolNames {
			t.Errorf("Log %d: Expected ToolNames '%s', got '%s'", idx, expected.toolNames, log.ToolNames)
		}
	}
}

func TestAggregatedStatsPersistAcrossRestart(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	baseTime := time.Now()
	logs := []*RequestLog{
		{
			ProxyKeyName:  "key-a",
			ProxyKeyID:    "key-a-id",
			ProviderGroup: "group-a",
			OpenRouterKey: "masked-a",
			Model:         "model-a",
			RequestBody:   "{}",
			ResponseBody:  "{}",
			StatusCode:    200,
			IsStream:      false,
			Duration:      120,
			TokensUsed:    42,
			ClientIP:      "127.0.0.1",
			CreatedAt:     baseTime,
		},
		{
			ProxyKeyName:  "key-a",
			ProxyKeyID:    "key-a-id",
			ProviderGroup: "group-a",
			OpenRouterKey: "masked-a",
			Model:         "model-a",
			RequestBody:   "{}",
			ResponseBody:  "{}",
			StatusCode:    500,
			IsStream:      false,
			Duration:      80,
			TokensUsed:    0,
			Error:         "boom",
			ClientIP:      "127.0.0.1",
			CreatedAt:     baseTime.Add(2 * time.Minute),
		},
	}

	for _, row := range logs {
		if err := db.InsertRequestLog(row); err != nil {
			t.Fatalf("Failed to insert request log: %v", err)
		}
	}

	if err := db.Close(); err != nil {
		t.Fatalf("Failed to close database: %v", err)
	}

	db, err = NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to reopen database: %v", err)
	}
	defer db.Close()

	totalStats, err := db.GetTotalTokensStats()
	if err != nil {
		t.Fatalf("Failed to get total token stats: %v", err)
	}
	if totalStats.TotalRequests != 2 {
		t.Fatalf("Expected 2 total requests, got %d", totalStats.TotalRequests)
	}
	if totalStats.SuccessRequests != 1 {
		t.Fatalf("Expected 1 success request, got %d", totalStats.SuccessRequests)
	}
	if totalStats.TotalTokens != 42 {
		t.Fatalf("Expected 42 total tokens, got %d", totalStats.TotalTokens)
	}

	count, err := db.GetRequestCountWithFilter(&LogFilter{})
	if err != nil {
		t.Fatalf("Failed to get request count: %v", err)
	}
	if count != 2 {
		t.Fatalf("Expected count 2, got %d", count)
	}

	statusStats, err := db.GetStatusStats(&LogFilter{})
	if err != nil {
		t.Fatalf("Failed to get status stats: %v", err)
	}
	if statusStats.Success != 1 || statusStats.Error != 1 {
		t.Fatalf("Expected status stats 1/1, got %d/%d", statusStats.Success, statusStats.Error)
	}

	proxyStats, err := db.GetProxyKeyStats()
	if err != nil {
		t.Fatalf("Failed to get proxy key stats: %v", err)
	}
	if len(proxyStats) != 1 || proxyStats[0].TotalRequests != 2 {
		t.Fatalf("Expected one proxy key stat with 2 requests, got %+v", proxyStats)
	}

	modelStats, err := db.GetModelStatsWithFilter(nil)
	if err != nil {
		t.Fatalf("Failed to get model stats: %v", err)
	}
	if len(modelStats) != 1 || modelStats[0].TotalRequests != 1 {
		t.Fatalf("Expected one model stat with 1 success request, got %+v", modelStats)
	}
}

func TestAggregatedStatsRebuildAfterClearErrorLogs(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := NewDatabase(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	now := time.Now()
	rows := []*RequestLog{
		{
			ProxyKeyName:  "key-a",
			ProxyKeyID:    "key-a-id",
			ProviderGroup: "group-a",
			OpenRouterKey: "masked-a",
			Model:         "model-a",
			RequestBody:   "{}",
			ResponseBody:  "{}",
			StatusCode:    200,
			IsStream:      false,
			Duration:      100,
			TokensUsed:    30,
			ClientIP:      "127.0.0.1",
			CreatedAt:     now,
		},
		{
			ProxyKeyName:  "key-b",
			ProxyKeyID:    "key-b-id",
			ProviderGroup: "group-b",
			OpenRouterKey: "masked-b",
			Model:         "model-b",
			RequestBody:   "{}",
			ResponseBody:  "{}",
			StatusCode:    429,
			IsStream:      false,
			Duration:      50,
			TokensUsed:    0,
			Error:         "rate limited",
			ClientIP:      "127.0.0.1",
			CreatedAt:     now.Add(time.Minute),
		},
	}

	for _, row := range rows {
		if err := db.InsertRequestLog(row); err != nil {
			t.Fatalf("Failed to insert request log: %v", err)
		}
	}

	deleted, err := db.ClearErrorRequestLogs()
	if err != nil {
		t.Fatalf("Failed to clear error logs: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("Expected to delete 1 error log, got %d", deleted)
	}

	totalStats, err := db.GetTotalTokensStats()
	if err != nil {
		t.Fatalf("Failed to get total stats after clear: %v", err)
	}
	if totalStats.TotalRequests != 1 || totalStats.SuccessRequests != 1 || totalStats.TotalTokens != 30 {
		t.Fatalf("Unexpected totals after clear: %+v", totalStats)
	}

	statusStats, err := db.GetStatusStats(&LogFilter{})
	if err != nil {
		t.Fatalf("Failed to get status stats after clear: %v", err)
	}
	if statusStats.Success != 1 || statusStats.Error != 0 {
		t.Fatalf("Unexpected status stats after clear: %+v", statusStats)
	}
}
