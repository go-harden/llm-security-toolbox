package service

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests that require a running Burp Suite instance.
// These tests will skip automatically if Burp is not available.

func TestBurp_ProxyList(t *testing.T) {
	srv, cleanup := setupBurpServer(t)
	t.Cleanup(cleanup)

	// Query proxy list (may be empty or have entries depending on Burp state)
	w := doBurpRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.OK, "response should be OK: %v", resp.Error)

	var listResp ProxyListResponse
	require.NoError(t, json.Unmarshal(resp.Data, &listResp))

	t.Logf("Burp proxy list: %d aggregates, %d flows", len(listResp.Aggregates), len(listResp.Flows))
}

func TestBurp_ProxyListWithFilters(t *testing.T) {
	srv, cleanup := setupBurpServer(t)
	t.Cleanup(cleanup)

	// Query with method filter
	w := doBurpRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{
		Method: "GET,POST",
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.OK)

	var listResp ProxyListResponse
	require.NoError(t, json.Unmarshal(resp.Data, &listResp))

	// With filters, should return flows not aggregates
	t.Logf("Filtered results: %d flows", len(listResp.Flows))

	// Verify all returned flows match the filter
	for _, flow := range listResp.Flows {
		assert.True(t, flow.Method == "GET" || flow.Method == "POST",
			"method should be GET or POST, got %s", flow.Method)
	}
}

func TestBurp_ProxyExportAndReplay(t *testing.T) {
	srv, cleanup := setupBurpServer(t)
	t.Cleanup(cleanup)

	// First get a flow ID from proxy list
	w := doBurpRequest(t, srv, "POST", "/proxy/list", ProxyListRequest{
		Method: "GET", // Filter to get flows
	})

	require.Equal(t, http.StatusOK, w.Code)

	var listAPIResp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listAPIResp))
	require.True(t, listAPIResp.OK)

	var listResp ProxyListResponse
	require.NoError(t, json.Unmarshal(listAPIResp.Data, &listResp))

	if len(listResp.Flows) == 0 {
		t.Skip("no proxy history entries available for export test")
	}

	flowID := listResp.Flows[0].FlowID
	t.Logf("Testing with flow ID: %s", flowID)

	// Export the flow
	w = doBurpRequest(t, srv, "POST", "/proxy/export", ProxyExportRequest{FlowID: flowID})

	require.Equal(t, http.StatusOK, w.Code)

	var exportAPIResp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &exportAPIResp))
	require.True(t, exportAPIResp.OK, "export failed: %v", exportAPIResp.Error)

	var exportResp ProxyExportResponse
	require.NoError(t, json.Unmarshal(exportAPIResp.Data, &exportResp))

	t.Logf("Exported to bundle: %s at %s", exportResp.BundleID, exportResp.BundlePath)

	// Verify bundle files
	assert.FileExists(t, filepath.Join(exportResp.BundlePath, "request.http"))
	assert.FileExists(t, filepath.Join(exportResp.BundlePath, "body"))
	assert.FileExists(t, filepath.Join(exportResp.BundlePath, "request.meta.json"))

	// Read and log the request
	reqContent, err := os.ReadFile(filepath.Join(exportResp.BundlePath, "request.http"))
	require.NoError(t, err)
	t.Logf("Exported request:\n%s", string(reqContent))

	// Replay the request from the bundle
	w = doBurpRequest(t, srv, "POST", "/replay/send", ReplaySendRequest{
		BundlePath: exportResp.BundlePath,
	})

	require.Equal(t, http.StatusOK, w.Code)

	var replayAPIResp APIResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &replayAPIResp))
	require.True(t, replayAPIResp.OK, "replay failed: %v", replayAPIResp.Error)

	var replayResp ReplaySendResponse
	require.NoError(t, json.Unmarshal(replayAPIResp.Data, &replayResp))

	t.Logf("Replay result: ID=%s, Status=%d, Duration=%s, Size=%d",
		replayResp.ReplayID, replayResp.Status, replayResp.Duration, replayResp.RespSize)

	assert.NotEmpty(t, replayResp.ReplayID)
	assert.NotEmpty(t, replayResp.Duration)
}
