package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jentfoo/llm-security-toolbox/sectool/config"
	"github.com/jentfoo/llm-security-toolbox/sectool/service/testutil"
)

// Integration tests for Burp MCP client.
// These tests will skip automatically if Burp is not available.

func connectOrSkip(t *testing.T, ctx context.Context) *BurpClient {
	t.Helper()

	// Acquire exclusive lock to prevent concurrent MCP connections across packages
	_ = testutil.AcquireBurpLock(t)

	client := New(config.DefaultBurpMCPURL)
	err := client.Connect(ctx)
	if err != nil {
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestBurpConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	assert.True(t, client.IsConnected())
	assert.Equal(t, config.DefaultBurpMCPURL, client.URL())
}

func TestBurpConnectTwice(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	// Second connect should be no-op
	err := client.Connect(ctx)
	require.NoError(t, err)
	assert.True(t, client.IsConnected())
}

func TestBurpGetProxyHistory_Empty(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	// Fetch with moderately high offset to likely get empty results
	// Using 9999 instead of 999999 to avoid potential performance issues with Burp MCP
	entries, err := client.GetProxyHistory(ctx, 10, 9999)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestBurpGetProxyHistory_FirstPage(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	entries, err := client.GetProxyHistory(ctx, 5, 0)
	require.NoError(t, err)

	t.Logf("Retrieved %d entries from first page", len(entries))
	for i, entry := range entries {
		// Validate structure
		assert.NotEmpty(t, entry.Request, "entry %d should have request", i)

		// Log first line of request
		firstLine := extractFirstLine(entry.Request)
		t.Logf("  [%d] Request: %s", i, firstLine)

		if entry.Response != "" {
			firstLine = extractFirstLine(entry.Response)
			t.Logf("      Response: %s", firstLine)
		}
	}
}

func TestBurpGetProxyHistory_Pagination(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	// Fetch first page
	page1, err := client.GetProxyHistory(ctx, 3, 0)
	require.NoError(t, err)

	if len(page1) < 3 {
		t.Skipf("Need at least 3 entries in proxy history for pagination test, got %d", len(page1))
	}

	// Fetch second page
	page2, err := client.GetProxyHistory(ctx, 3, 3)
	require.NoError(t, err)

	t.Logf("Page 1: %d entries, Page 2: %d entries", len(page1), len(page2))

	// Verify pages are different (by comparing first request lines)
	if len(page2) > 0 {
		assert.NotEqual(t,
			extractFirstLine(page1[0].Request),
			extractFirstLine(page2[0].Request),
			"pagination should return different entries")
	}
}

func TestBurpGetProxyHistoryRaw(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	raw, err := client.GetProxyHistoryRaw(ctx, 2, 0)
	require.NoError(t, err)

	t.Logf("Raw response length: %d bytes", len(raw))

	// Raw should be NDJSON format or end-of-items marker
	if raw != "" && raw != endOfItemsMarker {
		assert.True(t, strings.Contains(raw, `"request"`) || strings.Contains(raw, "Reached end"))
	}
}

func TestBurpGetProxyHistoryRegex_NoMatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	// Use a regex that's unlikely to match anything
	entries, err := client.GetProxyHistoryRegex(ctx, "UNLIKELYTOMATCH12345XYZ", 10, 0)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestBurpGetProxyHistoryRegex_MatchHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	// Match HTTP requests (very broad pattern)
	entries, err := client.GetProxyHistoryRegex(ctx, "HTTP/1\\.[01]", 5, 0)
	require.NoError(t, err)

	t.Logf("Regex matched %d entries", len(entries))
	for i, entry := range entries {
		assert.Contains(t, entry.Request, "HTTP/1", "entry %d should contain HTTP version", i)
	}
}

func TestBurpGetProxyHistoryRegex_MatchHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	// Match Host header
	entries, err := client.GetProxyHistoryRegex(ctx, "Host:", 5, 0)
	require.NoError(t, err)

	t.Logf("Host header matched %d entries", len(entries))
}

func TestBurpSetInterceptState(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	// Turn off interception
	err := client.SetInterceptState(ctx, false)
	require.NoError(t, err)

	// Turn it back on (but immediately off to not block user's Burp)
	err = client.SetInterceptState(ctx, true)
	require.NoError(t, err)

	err = client.SetInterceptState(ctx, false)
	require.NoError(t, err)
}

func TestBurpCreateRepeaterTab(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	params := RepeaterTabParams{
		TabName:        "sectool-test",
		Content:        "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
		TargetHostname: "example.com",
		TargetPort:     443,
		UsesHTTPS:      true,
	}
	err := client.CreateRepeaterTab(ctx, params)
	require.NoError(t, err)
}

func TestBurpCreateRepeaterTab_HTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	params := RepeaterTabParams{
		TabName:        "sectool-http-test",
		Content:        "GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n",
		TargetHostname: "httpbin.org",
		TargetPort:     80,
		UsesHTTPS:      false,
	}
	err := client.CreateRepeaterTab(ctx, params)
	require.NoError(t, err)
}

func TestBurpSendHTTP1Request(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	params := SendRequestParams{
		Content:        "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nUser-Agent: sectool-test\r\nConnection: close\r\n\r\n",
		TargetHostname: "httpbin.org",
		TargetPort:     443,
		UsesHTTPS:      true,
	}
	response, err := client.SendHTTP1Request(ctx, params)
	require.NoError(t, err)

	t.Logf("Response length: %d bytes", len(response))
	t.Logf("Response preview: %s", truncate(response, 500))

	// Should have HTTP response
	assert.Contains(t, response, "HTTP/")
}

func TestBurpSendHTTP1Request_HTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	params := SendRequestParams{
		Content:        "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nUser-Agent: sectool-test\r\nConnection: close\r\n\r\n",
		TargetHostname: "httpbin.org",
		TargetPort:     80,
		UsesHTTPS:      false,
	}

	response, err := client.SendHTTP1Request(ctx, params)
	require.NoError(t, err)

	t.Logf("HTTP Response length: %d bytes", len(response))
	assert.Contains(t, response, "HTTP/")
}

func TestBurpSendHTTP1Request_POST(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	body := `{"test": "data"}`
	params := SendRequestParams{
		Content: "POST /post HTTP/1.1\r\n" +
			"Host: httpbin.org\r\n" +
			"Content-Type: application/json\r\n" +
			"Content-Length: " + itoa(len(body)) + "\r\n" +
			"Connection: close\r\n\r\n" +
			body,
		TargetHostname: "httpbin.org",
		TargetPort:     443,
		UsesHTTPS:      true,
	}

	response, err := client.SendHTTP1Request(ctx, params)
	require.NoError(t, err)

	t.Logf("POST Response length: %d bytes", len(response))
	assert.Contains(t, response, "HTTP/")
	// httpbin echoes back the posted data
	assert.Contains(t, response, "test")
}

func TestBurpCloseAndReconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := New(config.DefaultBurpMCPURL)
	err := client.Connect(ctx)
	if err != nil {
		t.Skipf("Burp MCP not available: %v", err)
	}

	assert.True(t, client.IsConnected())

	// Close
	err = client.Close()
	require.NoError(t, err)
	assert.False(t, client.IsConnected())

	// Reconnect
	err = client.Connect(ctx)
	require.NoError(t, err)
	assert.True(t, client.IsConnected())

	_ = client.Close()
}

func TestBurpLargeHistoryFetch(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	// Fetch a larger batch to test buffer handling and JSON sanitization
	entries, err := client.GetProxyHistory(ctx, 50, 0)
	require.NoError(t, err)

	t.Logf("Large fetch returned %d entries", len(entries))

	// Validate all entries have structure
	for i, entry := range entries {
		assert.NotEmpty(t, entry.Request, "entry %d should have request", i)
	}
}

func extractFirstLine(s string) string {
	if idx := strings.IndexAny(s, "\r\n"); idx > 0 {
		return s[:idx]
	}
	if len(s) > 100 {
		return s[:100] + "..."
	}
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestBurpSendHTTP2Request(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	params := SendHTTP2RequestParams{
		PseudoHeaders: map[string]string{
			":method":    "GET",
			":path":      "/get",
			":authority": "httpbin.org",
			":scheme":    "https",
		},
		Headers: map[string]string{
			"User-Agent": "sectool-test",
		},
		TargetHostname: "httpbin.org",
		TargetPort:     443,
		UsesHTTPS:      true,
	}
	response, err := client.SendHTTP2Request(ctx, params)
	require.NoError(t, err)

	t.Logf("HTTP/2 Response length: %d bytes", len(response))
	t.Logf("HTTP/2 Response preview: %s", truncate(response, 500))

	// Should have HTTP response
	assert.Contains(t, response, "HTTP/")
}

func TestBurpSendToIntruder(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	params := IntruderParams{
		TabName:        "sectool-intruder-test",
		Content:        "GET /get?param=FUZZ HTTP/1.1\r\nHost: httpbin.org\r\n\r\n",
		TargetHostname: "httpbin.org",
		TargetPort:     443,
		UsesHTTPS:      true,
	}
	err := client.SendToIntruder(ctx, params)
	require.NoError(t, err)
}

func TestBurpGetProxyWebsocketHistory_Empty(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	// Fetch with high offset to likely get empty results
	entries, err := client.GetProxyWebsocketHistory(ctx, 10, 999999)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestBurpGetProxyWebsocketHistory_FirstPage(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	entries, err := client.GetProxyWebsocketHistory(ctx, 10, 0)
	require.NoError(t, err)

	t.Logf("Retrieved %d WebSocket history entries", len(entries))
	for i, entry := range entries {
		t.Logf("  [%d] %s: %s", i, entry.Direction, truncate(entry.Payload, 100))
	}
}

func TestBurpGetProxyWebsocketHistoryRaw(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	raw, err := client.GetProxyWebsocketHistoryRaw(ctx, 5, 0)
	require.NoError(t, err)

	t.Logf("Raw WebSocket history length: %d bytes", len(raw))
}

func TestBurpGetProxyWebsocketHistoryRegex_NoMatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	entries, err := client.GetProxyWebsocketHistoryRegex(ctx, "UNLIKELYTOMATCH12345XYZ", 10, 0)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestBurpSetTaskExecutionEngineState(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	// Pause the engine (running=false)
	err := client.SetTaskExecutionEngineState(ctx, false)
	require.NoError(t, err)

	// Resume immediately (running=true)
	err = client.SetTaskExecutionEngineState(ctx, true)
	require.NoError(t, err)
}

func TestBurpGetActiveEditorContents(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	// This may return empty or error if no editor is active
	contents, err := client.GetActiveEditorContents(ctx)
	if err != nil {
		t.Logf("GetActiveEditorContents returned error (expected if no editor active): %v", err)
		return
	}

	t.Logf("Active editor contents length: %d bytes", len(contents))
	if contents != "" {
		t.Logf("Contents preview: %s", truncate(contents, 200))
	}
}

func TestBurpSetActiveEditorContents(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	t.Cleanup(cancel)

	client := connectOrSkip(t, ctx)

	// This may fail if no editor is active
	testContent := "GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
	err := client.SetActiveEditorContents(ctx, testContent)
	if err != nil {
		t.Logf("SetActiveEditorContents returned error (expected if no editor active): %v", err)
		return
	}

	t.Log("SetActiveEditorContents succeeded")
}
