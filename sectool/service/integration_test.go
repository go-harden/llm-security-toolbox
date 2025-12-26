package service

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jentfoo/llm-security-toolbox/sectool/config"
	"github.com/jentfoo/llm-security-toolbox/sectool/service/mcp"
	"github.com/jentfoo/llm-security-toolbox/sectool/service/testutil"
)

func connectBurpOrSkip(t *testing.T) *mcp.BurpClient {
	t.Helper()

	// Acquire exclusive lock to prevent concurrent MCP connections across packages
	_ = testutil.AcquireBurpLock(t)

	client := mcp.New(config.DefaultBurpMCPURL)
	err := client.Connect(t.Context())
	if err != nil {
		t.Skipf("Burp MCP not available at %s: %v", config.DefaultBurpMCPURL, err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func setupBurpServer(t *testing.T) (*Server, func()) {
	t.Helper()

	_ = connectBurpOrSkip(t)

	workDir := t.TempDir()

	srv, err := NewServer(DaemonFlags{
		WorkDir:    workDir,
		BurpMCPURL: config.DefaultBurpMCPURL,
	})
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Run(t.Context())
	}()
	srv.WaitTillStarted()

	cleanup := func() {
		srv.RequestShutdown()
		<-serverErr
	}

	return srv, cleanup
}

func doBurpRequest(t *testing.T, srv *Server, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()

	var reqBody bytes.Buffer
	if body != nil {
		err := json.NewEncoder(&reqBody).Encode(body)
		require.NoError(t, err)
	}

	req := httptest.NewRequest(method, path, &reqBody)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	srv.routes().ServeHTTP(w, req)
	return w
}

// TestParseBurpResponse_Integration validates that parseBurpResponse correctly extracts
// headers and body from real Burp MCP responses.
func TestParseBurpResponse_Integration(t *testing.T) {
	client := connectBurpOrSkip(t)

	params := mcp.SendRequestParams{
		Content:        "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n",
		TargetHostname: "httpbin.org",
		TargetPort:     443,
		UsesHTTPS:      true,
	}
	response, err := client.SendHTTP1Request(t.Context(), params)
	require.NoError(t, err)

	t.Logf("Raw Burp response length: %d bytes", len(response))

	// Test the parsing function
	headers, body, err := parseBurpResponse(response)
	require.NoError(t, err, "parseBurpResponse should succeed")

	// Validate headers structure
	assert.True(t, bytes.HasPrefix(headers, []byte("HTTP/")), "headers should start with HTTP/")
	assert.True(t, bytes.HasSuffix(headers, []byte("\r\n\r\n")), "headers should end with CRLF CRLF")

	// Validate status can be extracted
	resp, err := readResponseBytes(headers)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, 200, resp.StatusCode)

	// httpbin /get returns JSON body
	assert.NotEmpty(t, body, "body should not be empty")
	assert.True(t, bytes.Contains(body, []byte("httpbin.org")), "body should contain httpbin.org")

	t.Logf("Parsed headers length: %d, body length: %d", len(headers), len(body))
	t.Logf("Headers preview:\n%s", truncateBytes(headers, 300))
}

func truncateBytes(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "..."
}
