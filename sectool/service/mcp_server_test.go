package service

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jentfoo/llm-security-toolbox/sectool/config"
	"github.com/jentfoo/llm-security-toolbox/sectool/service/testutil"
)

// Integration tests for the MCP server that require a running Burp Suite instance.
// These tests will skip automatically if Burp is not available.

func setupMCPServer(t *testing.T) (*Server, *client.Client, func()) {
	t.Helper()

	// Acquire exclusive lock to prevent concurrent MCP connections
	_ = testutil.AcquireBurpLock(t)

	// Verify Burp is available
	burpClient := connectBurpOrSkipForMCP(t)
	_ = burpClient.Close()

	workDir := t.TempDir()
	srv, err := NewServer(DaemonFlags{
		WorkDir:    workDir,
		BurpMCPURL: config.DefaultBurpMCPURL,
		MCP:        true,
		MCPPort:    0, // Let OS pick a port
	})
	require.NoError(t, err)

	// Override to use a random port
	srv.mcpPort = 0

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run(t.Context())
	}()
	srv.WaitTillStarted()

	// Get the actual port the MCP server is listening on
	require.NotNil(t, srv.mcpServer, "MCP server should be started")

	// Use in-process client to avoid SSE connection issues
	mcpClient, err := client.NewInProcessClient(srv.mcpServer.server)
	require.NoError(t, err)

	// Initialize the MCP connection
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	_, err = mcpClient.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ClientInfo: mcp.Implementation{
				Name:    "sectool-test",
				Version: "1.0.0",
			},
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		},
	})
	require.NoError(t, err)

	cleanup := func() {
		_ = mcpClient.Close()
		srv.RequestShutdown()
		<-serverErr
	}

	return srv, mcpClient, cleanup
}

func connectBurpOrSkipForMCP(t *testing.T) *client.Client {
	t.Helper()

	burpClient, err := client.NewSSEMCPClient(config.DefaultBurpMCPURL)
	if err != nil {
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}

	// Start the SSE transport
	if err := burpClient.Start(context.Background()); err != nil {
		_ = burpClient.Close()
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, err = burpClient.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ClientInfo: mcp.Implementation{
				Name:    "sectool-test-check",
				Version: "1.0.0",
			},
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		},
	})
	if err != nil {
		_ = burpClient.Close()
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}

	return burpClient
}

func callTool(t *testing.T, mcpClient *client.Client, name string, args map[string]interface{}) *mcp.CallToolResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	result, err := mcpClient.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      name,
			Arguments: args,
		},
	})
	require.NoError(t, err)
	return result
}

func extractText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()

	require.NotEmpty(t, result.Content, "result should have content")
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			return tc.Text
		}
	}
	t.Fatal("no text content found in result")
	return ""
}

// =============================================================================
// Tool List Tests
// =============================================================================

func TestMCP_ListTools(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	result, err := mcpClient.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)

	expectedTools := []string{
		"proxy_summary",
		"proxy_list",
		"proxy_get",
		"proxy_rule_list",
		"proxy_rule_add",
		"proxy_rule_update",
		"proxy_rule_delete",
		"replay_send",
		"replay_get",
		"oast_create",
		"oast_poll",
		"oast_get",
		"oast_list",
		"oast_delete",
		"encode_url",
		"encode_base64",
		"encode_html",
	}

	toolNames := make([]string, len(result.Tools))
	for i, tool := range result.Tools {
		toolNames[i] = tool.Name
	}

	for _, expected := range expectedTools {
		assert.Contains(t, toolNames, expected, "tool %s should be registered", expected)
	}
}

// =============================================================================
// Proxy Summary Tests
// =============================================================================

func TestMCP_ProxySummary(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	// proxy_summary returns aggregates
	result := callTool(t, mcpClient, "proxy_summary", nil)
	assert.False(t, result.IsError, "proxy_summary should succeed")

	text := extractText(t, result)
	var resp ProxySummaryResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	t.Logf("proxy_summary: %d aggregates", len(resp.Aggregates))
}

// =============================================================================
// Proxy List Tests
// =============================================================================

func TestMCP_ProxyListRequiresFilters(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	// proxy_list without filters should error
	result := callTool(t, mcpClient, "proxy_list", nil)
	assert.True(t, result.IsError, "proxy_list without filters should fail")
}

func TestMCP_ProxyListWithFilters(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	// Query with method filter - should return flows
	result := callTool(t, mcpClient, "proxy_list", map[string]interface{}{
		"method": "GET,POST",
	})
	assert.False(t, result.IsError, "proxy_list with filters should succeed")

	text := extractText(t, result)
	var resp ProxyListResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	t.Logf("proxy_list filtered: %d flows", len(resp.Flows))

	for _, flow := range resp.Flows {
		assert.True(t, flow.Method == "GET" || flow.Method == "POST",
			"method should be GET or POST, got %s", flow.Method)
	}
}

func TestMCP_ProxyListWithLimit(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	result := callTool(t, mcpClient, "proxy_list", map[string]interface{}{
		"method": "GET",
		"limit":  5,
	})
	assert.False(t, result.IsError)

	text := extractText(t, result)
	var resp ProxyListResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	assert.LessOrEqual(t, len(resp.Flows), 5, "should respect limit")
}

// =============================================================================
// Proxy Get Tests
// =============================================================================

func TestMCP_ProxyGet(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	// Get a flow ID from proxy list
	listResult := callTool(t, mcpClient, "proxy_list", map[string]interface{}{
		"method": "GET",
	})
	require.False(t, listResult.IsError)

	text := extractText(t, listResult)
	var listResp ProxyListResponse
	require.NoError(t, json.Unmarshal([]byte(text), &listResp))

	if len(listResp.Flows) == 0 {
		t.Skip("no proxy history entries available")
	}

	flowID := listResp.Flows[0].FlowID

	// Get full flow data
	result := callTool(t, mcpClient, "proxy_get", map[string]interface{}{
		"flow_id": flowID,
	})
	assert.False(t, result.IsError, "proxy_get should succeed: %s", extractText(t, result))

	text = extractText(t, result)
	var resp ProxyGetResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	assert.Equal(t, flowID, resp.FlowID)
	assert.NotEmpty(t, resp.Method)
	assert.NotEmpty(t, resp.URL)
	assert.NotEmpty(t, resp.ReqHeaders)
	assert.NotEmpty(t, resp.RespHeaders)
	assert.Positive(t, resp.Status)
	t.Logf("proxy_get: method=%s url=%s status=%d req_size=%d resp_size=%d",
		resp.Method, resp.URL, resp.Status, resp.ReqSize, resp.RespSize)
}

func TestMCP_ProxyGetValidation(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	t.Run("missing_flow_id", func(t *testing.T) {
		result := callTool(t, mcpClient, "proxy_get", map[string]interface{}{})
		assert.True(t, result.IsError, "should fail without flow_id")
		assert.Contains(t, extractText(t, result), "flow_id is required")
	})

	t.Run("invalid_flow_id", func(t *testing.T) {
		result := callTool(t, mcpClient, "proxy_get", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError, "should fail with invalid flow_id")
		assert.Contains(t, extractText(t, result), "not found")
	})
}

// =============================================================================
// Proxy Rule Tests
// =============================================================================

func TestMCP_ProxyRulesCRUD(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	// Clean up any existing test rules
	cleanupMCPRules(t, mcpClient)

	t.Run("list_empty", func(t *testing.T) {
		result := callTool(t, mcpClient, "proxy_rule_list", nil)
		assert.False(t, result.IsError)

		text := extractText(t, result)
		var resp RuleListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))
		assert.Empty(t, resp.Rules)
	})

	var createdRuleID string

	t.Run("add_rule", func(t *testing.T) {
		result := callTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"type":    "request_header",
			"label":   "mcp-test-add",
			"replace": "X-MCP-Test: value",
		})
		assert.False(t, result.IsError, "add should succeed: %s", extractText(t, result))

		text := extractText(t, result)
		var rule RuleEntry
		require.NoError(t, json.Unmarshal([]byte(text), &rule))
		assert.NotEmpty(t, rule.RuleID)
		assert.Equal(t, "mcp-test-add", rule.Label)
		assert.Equal(t, "request_header", rule.Type)
		createdRuleID = rule.RuleID
	})

	t.Run("list_after_add", func(t *testing.T) {
		result := callTool(t, mcpClient, "proxy_rule_list", nil)
		assert.False(t, result.IsError)

		text := extractText(t, result)
		var resp RuleListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))
		require.Len(t, resp.Rules, 1)
		assert.Equal(t, createdRuleID, resp.Rules[0].RuleID)
	})

	t.Run("update_rule", func(t *testing.T) {
		result := callTool(t, mcpClient, "proxy_rule_update", map[string]interface{}{
			"rule_id": createdRuleID,
			"type":    "request_body",
			"label":   "mcp-test-updated",
			"match":   "old",
			"replace": "new",
		})
		assert.False(t, result.IsError, "update should succeed: %s", extractText(t, result))

		text := extractText(t, result)
		var rule RuleEntry
		require.NoError(t, json.Unmarshal([]byte(text), &rule))
		assert.Equal(t, "mcp-test-updated", rule.Label)
		assert.Equal(t, "request_body", rule.Type)
	})

	t.Run("delete_rule", func(t *testing.T) {
		result := callTool(t, mcpClient, "proxy_rule_delete", map[string]interface{}{
			"rule_id": createdRuleID,
		})
		assert.False(t, result.IsError, "delete should succeed")

		// Verify deleted
		listResult := callTool(t, mcpClient, "proxy_rule_list", nil)
		text := extractText(t, listResult)
		var resp RuleListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))
		assert.Empty(t, resp.Rules)
	})
}

func TestMCP_ProxyRuleValidation(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	t.Run("missing_type", func(t *testing.T) {
		result := callTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"replace": "X-Test: value",
		})
		assert.True(t, result.IsError, "should fail without type")
		assert.Contains(t, extractText(t, result), "type is required")
	})

	t.Run("invalid_type", func(t *testing.T) {
		result := callTool(t, mcpClient, "proxy_rule_add", map[string]interface{}{
			"type": "invalid_type",
		})
		assert.True(t, result.IsError, "should fail with invalid type")
		assert.Contains(t, extractText(t, result), "invalid rule type")
	})

	t.Run("missing_rule_id_delete", func(t *testing.T) {
		result := callTool(t, mcpClient, "proxy_rule_delete", map[string]interface{}{})
		assert.True(t, result.IsError, "should fail without rule_id")
		assert.Contains(t, extractText(t, result), "rule_id is required")
	})
}

func cleanupMCPRules(t *testing.T, mcpClient *client.Client) {
	t.Helper()

	result := callTool(t, mcpClient, "proxy_rule_list", nil)
	if result.IsError {
		return
	}

	text := extractText(t, result)
	var resp RuleListResponse
	if err := json.Unmarshal([]byte(text), &resp); err != nil {
		return
	}

	for _, rule := range resp.Rules {
		callTool(t, mcpClient, "proxy_rule_delete", map[string]interface{}{
			"rule_id": rule.RuleID,
		})
	}
}

// =============================================================================
// Replay Tests
// =============================================================================

func TestMCP_ReplaySendFromFlow(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	// Get a flow ID from proxy list
	listResult := callTool(t, mcpClient, "proxy_list", map[string]interface{}{
		"method": "GET",
	})
	require.False(t, listResult.IsError)

	text := extractText(t, listResult)
	var listResp ProxyListResponse
	require.NoError(t, json.Unmarshal([]byte(text), &listResp))

	if len(listResp.Flows) == 0 {
		t.Skip("no proxy history entries available")
	}

	flowID := listResp.Flows[0].FlowID

	// Replay from flow
	result := callTool(t, mcpClient, "replay_send", map[string]interface{}{
		"flow_id": flowID,
	})
	assert.False(t, result.IsError, "replay should succeed: %s", extractText(t, result))

	text = extractText(t, result)
	var resp ReplaySendResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	assert.NotEmpty(t, resp.ReplayID)
	assert.NotEmpty(t, resp.Duration)
	t.Logf("replay_send: id=%s status=%d duration=%s", resp.ReplayID, resp.Status, resp.Duration)
}

func TestMCP_ReplayWithModifications(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	// Get a flow ID
	listResult := callTool(t, mcpClient, "proxy_list", map[string]interface{}{
		"method": "GET",
	})
	require.False(t, listResult.IsError)

	text := extractText(t, listResult)
	var listResp ProxyListResponse
	require.NoError(t, json.Unmarshal([]byte(text), &listResp))

	if len(listResp.Flows) == 0 {
		t.Skip("no proxy history entries available")
	}

	flowID := listResp.Flows[0].FlowID

	// Replay with header modifications
	result := callTool(t, mcpClient, "replay_send", map[string]interface{}{
		"flow_id":        flowID,
		"add_headers":    []string{"X-MCP-Test: integration"},
		"remove_headers": []string{"Accept-Encoding"},
	})
	assert.False(t, result.IsError, "replay with modifications should succeed")

	text = extractText(t, result)
	var resp ReplaySendResponse
	require.NoError(t, json.Unmarshal([]byte(text), &resp))

	assert.NotEmpty(t, resp.ReplayID)
	t.Logf("replay with mods: status=%d", resp.Status)
}

func TestMCP_ReplayGet(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	// Get a flow ID and send replay
	listResult := callTool(t, mcpClient, "proxy_list", map[string]interface{}{
		"method": "GET",
	})
	require.False(t, listResult.IsError)

	text := extractText(t, listResult)
	var listResp ProxyListResponse
	require.NoError(t, json.Unmarshal([]byte(text), &listResp))

	if len(listResp.Flows) == 0 {
		t.Skip("no proxy history entries available")
	}

	flowID := listResp.Flows[0].FlowID

	// Send replay
	sendResult := callTool(t, mcpClient, "replay_send", map[string]interface{}{
		"flow_id": flowID,
	})
	require.False(t, sendResult.IsError)

	text = extractText(t, sendResult)
	var sendResp ReplaySendResponse
	require.NoError(t, json.Unmarshal([]byte(text), &sendResp))

	// Get full response
	getResult := callTool(t, mcpClient, "replay_get", map[string]interface{}{
		"replay_id": sendResp.ReplayID,
	})
	assert.False(t, getResult.IsError, "replay_get should succeed")

	text = extractText(t, getResult)
	var getResp ReplayGetResponse
	require.NoError(t, json.Unmarshal([]byte(text), &getResp))

	assert.Equal(t, sendResp.ReplayID, getResp.ReplayID)
	assert.NotEmpty(t, getResp.RespHeaders)
	assert.NotEmpty(t, getResp.RespBody)
	t.Logf("replay_get: status=%d size=%d", getResp.Status, getResp.RespSize)
}

func TestMCP_ReplayValidation(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	t.Run("missing_flow_id", func(t *testing.T) {
		result := callTool(t, mcpClient, "replay_send", map[string]interface{}{})
		assert.True(t, result.IsError, "should fail without flow_id")
		assert.Contains(t, extractText(t, result), "flow_id")
	})

	t.Run("invalid_flow_id", func(t *testing.T) {
		result := callTool(t, mcpClient, "replay_send", map[string]interface{}{
			"flow_id": "nonexistent",
		})
		assert.True(t, result.IsError, "should fail with invalid flow_id")
		assert.Contains(t, extractText(t, result), "not found")
	})

	t.Run("missing_replay_id", func(t *testing.T) {
		result := callTool(t, mcpClient, "replay_get", map[string]interface{}{})
		assert.True(t, result.IsError, "should fail without replay_id")
		assert.Contains(t, extractText(t, result), "replay_id is required")
	})

	t.Run("invalid_replay_id", func(t *testing.T) {
		result := callTool(t, mcpClient, "replay_get", map[string]interface{}{
			"replay_id": "nonexistent",
		})
		assert.True(t, result.IsError, "should fail with invalid replay_id")
		assert.Contains(t, extractText(t, result), "not found")
	})
}

// =============================================================================
// OAST Tests
// =============================================================================

func TestMCP_OastLifecycle(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	var oastID string
	var domain string

	t.Run("create", func(t *testing.T) {
		result := callTool(t, mcpClient, "oast_create", map[string]interface{}{
			"label": "mcp-test",
		})
		assert.False(t, result.IsError, "oast_create should succeed: %s", extractText(t, result))

		text := extractText(t, result)
		var resp OastCreateResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))

		assert.NotEmpty(t, resp.OastID)
		assert.NotEmpty(t, resp.Domain)
		assert.Equal(t, "mcp-test", resp.Label)

		oastID = resp.OastID
		domain = resp.Domain
		t.Logf("oast_create: id=%s domain=%s", oastID, domain)
	})

	t.Run("list", func(t *testing.T) {
		result := callTool(t, mcpClient, "oast_list", nil)
		assert.False(t, result.IsError)

		text := extractText(t, result)
		var resp OastListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))

		var found bool
		for _, sess := range resp.Sessions {
			if sess.OastID == oastID {
				found = true
				assert.Equal(t, domain, sess.Domain)
				break
			}
		}
		assert.True(t, found, "created session should appear in list")
	})

	t.Run("poll", func(t *testing.T) {
		result := callTool(t, mcpClient, "oast_poll", map[string]interface{}{
			"oast_id": oastID,
		})
		assert.False(t, result.IsError, "oast_poll should succeed")

		text := extractText(t, result)
		var resp OastPollResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))
		// Events may be empty, which is fine
		t.Logf("oast_poll: %d events", len(resp.Events))
	})

	t.Run("delete", func(t *testing.T) {
		result := callTool(t, mcpClient, "oast_delete", map[string]interface{}{
			"oast_id": oastID,
		})
		assert.False(t, result.IsError, "oast_delete should succeed")

		// Verify no longer in list
		listResult := callTool(t, mcpClient, "oast_list", nil)
		text := extractText(t, listResult)
		var resp OastListResponse
		require.NoError(t, json.Unmarshal([]byte(text), &resp))

		for _, sess := range resp.Sessions {
			assert.NotEqual(t, oastID, sess.OastID, "deleted session should not appear")
		}
	})
}

func TestMCP_OastValidation(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	t.Run("poll_missing_id", func(t *testing.T) {
		result := callTool(t, mcpClient, "oast_poll", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, extractText(t, result), "oast_id is required")
	})

	t.Run("get_missing_id", func(t *testing.T) {
		result := callTool(t, mcpClient, "oast_get", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, extractText(t, result), "oast_id is required")
	})

	t.Run("get_missing_event_id", func(t *testing.T) {
		result := callTool(t, mcpClient, "oast_get", map[string]interface{}{
			"oast_id": "test",
		})
		assert.True(t, result.IsError)
		assert.Contains(t, extractText(t, result), "event_id is required")
	})

	t.Run("delete_missing_id", func(t *testing.T) {
		result := callTool(t, mcpClient, "oast_delete", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, extractText(t, result), "oast_id is required")
	})
}

// =============================================================================
// Encode Tests
// =============================================================================

func TestMCP_EncodeURL(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	t.Run("encode", func(t *testing.T) {
		result := callTool(t, mcpClient, "encode_url", map[string]interface{}{
			"input": "hello world&test=<value>",
		})
		assert.False(t, result.IsError)

		text := extractText(t, result)
		assert.Equal(t, "hello+world%26test%3D%3Cvalue%3E", text)
	})

	t.Run("decode", func(t *testing.T) {
		result := callTool(t, mcpClient, "encode_url", map[string]interface{}{
			"input":  "hello+world%26test%3D%3Cvalue%3E",
			"decode": true,
		})
		assert.False(t, result.IsError)

		text := extractText(t, result)
		assert.Equal(t, "hello world&test=<value>", text)
	})

	t.Run("missing_input", func(t *testing.T) {
		result := callTool(t, mcpClient, "encode_url", map[string]interface{}{})
		assert.True(t, result.IsError)
		assert.Contains(t, extractText(t, result), "input is required")
	})
}

func TestMCP_EncodeBase64(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	t.Run("encode", func(t *testing.T) {
		result := callTool(t, mcpClient, "encode_base64", map[string]interface{}{
			"input": "hello world",
		})
		assert.False(t, result.IsError)

		text := extractText(t, result)
		assert.Equal(t, "aGVsbG8gd29ybGQ=", text)
	})

	t.Run("decode", func(t *testing.T) {
		result := callTool(t, mcpClient, "encode_base64", map[string]interface{}{
			"input":  "aGVsbG8gd29ybGQ=",
			"decode": true,
		})
		assert.False(t, result.IsError)

		text := extractText(t, result)
		assert.Equal(t, "hello world", text)
	})

	t.Run("invalid_base64", func(t *testing.T) {
		result := callTool(t, mcpClient, "encode_base64", map[string]interface{}{
			"input":  "not valid base64!!!",
			"decode": true,
		})
		assert.True(t, result.IsError)
		assert.Contains(t, extractText(t, result), "base64 decode error")
	})
}

func TestMCP_EncodeHTML(t *testing.T) {
	_, mcpClient, cleanup := setupMCPServer(t)
	defer cleanup()

	t.Run("encode", func(t *testing.T) {
		result := callTool(t, mcpClient, "encode_html", map[string]interface{}{
			"input": "<script>alert('xss')</script>",
		})
		assert.False(t, result.IsError)

		text := extractText(t, result)
		assert.Equal(t, "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;", text)
	})

	t.Run("decode", func(t *testing.T) {
		result := callTool(t, mcpClient, "encode_html", map[string]interface{}{
			"input":  "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;",
			"decode": true,
		})
		assert.False(t, result.IsError)

		text := extractText(t, result)
		assert.Equal(t, "<script>alert('xss')</script>", text)
	})
}
