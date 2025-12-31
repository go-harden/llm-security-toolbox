package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/jentfoo/llm-security-toolbox/sectool/config"
	"github.com/jentfoo/llm-security-toolbox/sectool/service/ids"
	"github.com/jentfoo/llm-security-toolbox/sectool/service/store"
)

// mcpServer wraps the MCP server and its dependencies.
type mcpServer struct {
	server    *server.MCPServer
	sseServer *server.SSEServer
	listener  net.Listener
	service   *Server
}

// newMCPServer creates a new MCP server instance.
func newMCPServer(svc *Server) *mcpServer {
	mcpSrv := server.NewMCPServer(
		"sectool",
		config.Version,
		server.WithToolCapabilities(false),
		server.WithLogging(),
	)

	m := &mcpServer{
		server:  mcpSrv,
		service: svc,
	}

	m.registerTools()

	return m
}

func (m *mcpServer) Start(port int) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	m.listener = listener

	m.sseServer = server.NewSSEServer(m.server,
		server.WithBaseURL("http://"+addr),
	)

	go func() {
		if err := http.Serve(listener, m.sseServer); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("MCP SSE server error: %v", err)
		}
	}()

	return nil
}

func (m *mcpServer) Addr() string {
	if m.listener != nil {
		return m.listener.Addr().String()
	}
	return ""
}

// Close stops the MCP server.
func (m *mcpServer) Close(ctx context.Context) error {
	if m.sseServer != nil {
		return m.sseServer.Shutdown(ctx)
	}
	return nil
}

// registerTools registers all MCP tools.
func (m *mcpServer) registerTools() {
	// Proxy tools
	m.server.AddTool(m.proxyListTool(), m.handleProxyList)
	m.server.AddTool(m.proxyRuleListTool(), m.handleProxyRuleList)
	m.server.AddTool(m.proxyRuleAddTool(), m.handleProxyRuleAdd)
	m.server.AddTool(m.proxyRuleUpdateTool(), m.handleProxyRuleUpdate)
	m.server.AddTool(m.proxyRuleDeleteTool(), m.handleProxyRuleDelete)

	// Replay tools
	m.server.AddTool(m.replaySendTool(), m.handleReplaySend)
	m.server.AddTool(m.replayGetTool(), m.handleReplayGet)

	// OAST tools
	m.server.AddTool(m.oastCreateTool(), m.handleOastCreate)
	m.server.AddTool(m.oastPollTool(), m.handleOastPoll)
	m.server.AddTool(m.oastGetTool(), m.handleOastGet)
	m.server.AddTool(m.oastListTool(), m.handleOastList)
	m.server.AddTool(m.oastDeleteTool(), m.handleOastDelete)

	// Encode tools
	m.server.AddTool(m.encodeURLTool(), m.handleEncodeURL)
	m.server.AddTool(m.encodeBase64Tool(), m.handleEncodeBase64)
	m.server.AddTool(m.encodeHTMLTool(), m.handleEncodeHTML)
}

func (m *mcpServer) proxyListTool() mcp.Tool {
	return mcp.NewTool("proxy_list",
		mcp.WithDescription(`Query HTTP proxy history captured by Burp Suite.

Without filters, returns aggregated summary grouped by (host, path, method, status),
sorted by count descending.

With filters, returns individual flow entries with flow_id for further operations.

Filters support glob patterns (* for any chars, ? for single char).`),
		mcp.WithString("host", mcp.Description("Filter by host (glob pattern, e.g., '*.example.com')")),
		mcp.WithString("path", mcp.Description("Filter by path (glob pattern, e.g., '/api/*')")),
		mcp.WithString("method", mcp.Description("Filter by HTTP method(s), comma-separated (e.g., 'GET,POST')")),
		mcp.WithString("status", mcp.Description("Filter by status code(s), comma-separated (e.g., '200,302')")),
		mcp.WithString("contains", mcp.Description("Filter by text in URL or headers (does not search body)")),
		mcp.WithString("contains_body", mcp.Description("Filter by text in request or response body")),
		mcp.WithString("since", mcp.Description("Show entries after this flow_id, or 'last' for entries since last query")),
		mcp.WithString("exclude_host", mcp.Description("Exclude hosts matching glob pattern")),
		mcp.WithString("exclude_path", mcp.Description("Exclude paths matching glob pattern")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of results to return")),
	)
}

func (m *mcpServer) proxyRuleListTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_list",
		mcp.WithDescription(`List proxy match and replace rules.

Rules modify requests/responses as they pass through the proxy.
Use websocket=true to list WebSocket-specific rules.`),
		mcp.WithBoolean("websocket", mcp.Description("List WebSocket rules instead of HTTP rules")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of rules to return")),
	)
}

func (m *mcpServer) proxyRuleAddTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_add",
		mcp.WithDescription(`Add a new proxy match and replace rule.

Rules are applied to traffic as it passes through the Burp proxy.

Types:
- request_header: Match/replace in request headers
- request_body: Match/replace in request body
- response_header: Match/replace in response headers
- response_body: Match/replace in response body

For header additions: only 'replace' is needed (adds header without matching).
For replacements: both 'match' and 'replace' are needed.

Set is_regex=true for regex patterns (Java regex syntax).`),
		mcp.WithString("type", mcp.Required(), mcp.Description("Rule type: request_header, request_body, response_header, response_body")),
		mcp.WithString("match", mcp.Description("Pattern to match")),
		mcp.WithString("replace", mcp.Description("Replacement text")),
		mcp.WithString("label", mcp.Description("Optional label for the rule")),
		mcp.WithBoolean("is_regex", mcp.Description("Treat match as regex pattern (Java regex syntax)")),
		mcp.WithBoolean("websocket", mcp.Description("Add as WebSocket rule instead of HTTP")),
	)
}

func (m *mcpServer) proxyRuleUpdateTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_update",
		mcp.WithDescription(`Update an existing proxy match and replace rule.

Searches both HTTP and WebSocket rules automatically.`),
		mcp.WithString("rule_id", mcp.Required(), mcp.Description("Rule ID or label to update")),
		mcp.WithString("type", mcp.Required(), mcp.Description("Rule type: request_header, request_body, response_header, response_body")),
		mcp.WithString("match", mcp.Description("Pattern to match")),
		mcp.WithString("replace", mcp.Description("Replacement text")),
		mcp.WithString("label", mcp.Description("Optional label for the rule")),
		mcp.WithBoolean("is_regex", mcp.Description("Treat match as regex pattern (Java regex syntax)")),
	)
}

func (m *mcpServer) proxyRuleDeleteTool() mcp.Tool {
	return mcp.NewTool("proxy_rule_delete",
		mcp.WithDescription("Delete a proxy match and replace rule. Searches both HTTP and WebSocket rules automatically."),
		mcp.WithString("rule_id", mcp.Required(), mcp.Description("Rule ID or label to delete")),
	)
}

func (m *mcpServer) replaySendTool() mcp.Tool {
	return mcp.NewTool("replay_send",
		mcp.WithDescription(`Send or replay an HTTP request with optional modifications.

Start with a flow_id from proxy_list as the base request, then apply modifications.

Request modifications:
- Headers: add/remove headers via add_headers/remove_headers, change target host
- Path/Query: modify URL path and query parameters
- Body: provide new body content or modify JSON fields

JSON body modifications (set_json, remove_json):
- Nested paths use dot notation: user.email, items[0].id
- Type inference: null/true/false are literals, numbers are parsed, {} and [] are objects/arrays
- Modification order: remove operations apply first, then set operations

Query string modifications (set_query, remove_query):
- Modification order: remove operations apply first, then set operations

Validation:
- Requests are validated before sending (structure, Content-Length, line endings)
- Validation errors prevent sending; use force=true to bypass (useful for testing malformed requests)

Note: Content-Length header is automatically updated when body changes.`),
		mcp.WithString("flow_id", mcp.Required(), mcp.Description("Flow ID from proxy_list to use as base request")),
		mcp.WithString("body", mcp.Description("Request body content (replaces existing body)")),
		mcp.WithString("target", mcp.Description("Override target URL (e.g., 'https://other.example.com')")),
		mcp.WithArray("add_headers", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Headers to add/replace (format: 'Name: Value')")),
		mcp.WithArray("remove_headers", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Header names to remove")),
		mcp.WithString("path", mcp.Description("Override request path")),
		mcp.WithString("query", mcp.Description("Override entire query string")),
		mcp.WithArray("set_query", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Query params to set (format: 'name=value')")),
		mcp.WithArray("remove_query", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("Query param names to remove")),
		mcp.WithArray("set_json", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("JSON fields to set (format: 'path=value', uses JSONPath)")),
		mcp.WithArray("remove_json", mcp.Items(map[string]interface{}{"type": "string"}), mcp.Description("JSON fields to remove (JSONPath)")),
		mcp.WithBoolean("follow_redirects", mcp.Description("Follow HTTP redirects")),
		mcp.WithString("timeout", mcp.Description("Request timeout (e.g., '30s', '1m')")),
		mcp.WithBoolean("force", mcp.Description("Skip request validation (for testing malformed requests)")),
	)
}

func (m *mcpServer) replayGetTool() mcp.Tool {
	return mcp.NewTool("replay_get",
		mcp.WithDescription(`Retrieve full response from a previous replay_send.

Returns the complete response including headers and base64-encoded body.
Replay results are ephemeral and cleared when the service restarts.`),
		mcp.WithString("replay_id", mcp.Required(), mcp.Description("Replay ID from replay_send response")),
	)
}

func (m *mcpServer) oastCreateTool() mcp.Tool {
	return mcp.NewTool("oast_create",
		mcp.WithDescription(`Create a new OAST (Out-of-Band Application Security Testing) session.

Returns a unique domain that can be used to detect out-of-band interactions
(DNS lookups, HTTP requests, SMTP, etc.) from target applications.

Use the returned domain in payloads to detect blind vulnerabilities like:
- Blind SSRF
- Blind XXE
- DNS exfiltration
- Log4Shell-style JNDI injection`),
		mcp.WithString("label", mcp.Description("Optional label to identify this session")),
	)
}

func (m *mcpServer) oastPollTool() mcp.Tool {
	return mcp.NewTool("oast_poll",
		mcp.WithDescription(`Poll for OAST interaction events.

Returns events (DNS, HTTP, SMTP, etc.) that occurred on the OAST domain.
Use 'wait' for long-polling to wait for events up to the specified duration (max 120s).
Use 'since' with an event_id to get only newer events, or 'last' for events since last poll.`),
		mcp.WithString("oast_id", mcp.Required(), mcp.Description("OAST session ID, label, or domain")),
		mcp.WithString("since", mcp.Description("Return events after this event_id, or 'last' for new events")),
		mcp.WithString("wait", mcp.Description("Long-poll duration (e.g., '30s', max 120s)")),
		mcp.WithNumber("limit", mcp.Description("Maximum number of events to return")),
	)
}

func (m *mcpServer) oastGetTool() mcp.Tool {
	return mcp.NewTool("oast_get",
		mcp.WithDescription("Get full details of a specific OAST event without truncation."),
		mcp.WithString("oast_id", mcp.Required(), mcp.Description("OAST session ID, label, or domain")),
		mcp.WithString("event_id", mcp.Required(), mcp.Description("Event ID from oast_poll")),
	)
}

func (m *mcpServer) oastListTool() mcp.Tool {
	return mcp.NewTool("oast_list",
		mcp.WithDescription("List active OAST sessions."),
		mcp.WithNumber("limit", mcp.Description("Maximum number of sessions to return")),
	)
}

func (m *mcpServer) oastDeleteTool() mcp.Tool {
	return mcp.NewTool("oast_delete",
		mcp.WithDescription("Delete an OAST session and stop monitoring its domain."),
		mcp.WithString("oast_id", mcp.Required(), mcp.Description("OAST session ID, label, or domain")),
	)
}

func (m *mcpServer) encodeURLTool() mcp.Tool {
	return mcp.NewTool("encode_url",
		mcp.WithDescription("URL encode or decode a string."),
		mcp.WithString("input", mcp.Required(), mcp.Description("String to encode or decode")),
		mcp.WithBoolean("decode", mcp.Description("Decode instead of encode")),
	)
}

func (m *mcpServer) encodeBase64Tool() mcp.Tool {
	return mcp.NewTool("encode_base64",
		mcp.WithDescription("Base64 encode or decode a string."),
		mcp.WithString("input", mcp.Required(), mcp.Description("String to encode or decode")),
		mcp.WithBoolean("decode", mcp.Description("Decode instead of encode")),
	)
}

func (m *mcpServer) encodeHTMLTool() mcp.Tool {
	return mcp.NewTool("encode_html",
		mcp.WithDescription("HTML entity encode or decode a string."),
		mcp.WithString("input", mcp.Required(), mcp.Description("String to encode or decode")),
		mcp.WithBoolean("decode", mcp.Description("Decode instead of encode")),
	)
}

func (m *mcpServer) handleProxyList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	listReq := &ProxyListRequest{
		Host:         req.GetString("host", ""),
		Path:         req.GetString("path", ""),
		Method:       req.GetString("method", ""),
		Status:       req.GetString("status", ""),
		Contains:     req.GetString("contains", ""),
		ContainsBody: req.GetString("contains_body", ""),
		Since:        req.GetString("since", ""),
		ExcludeHost:  req.GetString("exclude_host", ""),
		ExcludePath:  req.GetString("exclude_path", ""),
		Limit:        req.GetInt("limit", 0),
	}

	resp, err := m.service.processProxyList(ctx, listReq)
	if err != nil {
		return errorResult("failed to fetch proxy history: " + err.Error()), nil
	}

	return jsonResult(resp)
}

func (m *mcpServer) handleProxyRuleList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	websocket := req.GetBool("websocket", false)
	limit := req.GetInt("limit", 0)

	log.Printf("mcp/proxy_rule_list: websocket=%t", websocket)

	rules, err := m.service.httpBackend.ListRules(ctx, websocket)
	if err != nil {
		return errorResult("failed to list rules: " + err.Error()), nil
	}

	if limit > 0 && len(rules) > limit {
		rules = rules[:limit]
	}

	log.Printf("mcp/proxy_rule_list: returning %d rules", len(rules))
	return jsonResult(RuleListResponse{Rules: rules})
}

func (m *mcpServer) handleProxyRuleAdd(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ruleType := req.GetString("type", "")
	if ruleType == "" {
		return errorResult("type is required"), nil
	}
	if err := validateRuleType(ruleType); err != nil {
		return errorResult(err.Error()), nil
	}

	match := req.GetString("match", "")
	replace := req.GetString("replace", "")
	if match == "" && replace == "" {
		return errorResult("match or replace is required"), nil
	}

	websocket := req.GetBool("websocket", false)
	label := req.GetString("label", "")

	log.Printf("mcp/proxy_rule_add: type=%s label=%q websocket=%t", ruleType, label, websocket)

	rule, err := m.service.httpBackend.AddRule(ctx, websocket, ProxyRuleInput{
		Label:   label,
		Type:    ruleType,
		IsRegex: req.GetBool("is_regex", false),
		Match:   match,
		Replace: replace,
	})
	if err != nil {
		if errors.Is(err, ErrLabelExists) {
			return errorResult("label already exists: " + err.Error()), nil
		}
		return errorResult("failed to add rule: " + err.Error()), nil
	}

	log.Printf("mcp/proxy_rule_add: created rule %s", rule.RuleID)
	return jsonResult(rule)
}

func (m *mcpServer) handleProxyRuleUpdate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ruleID := req.GetString("rule_id", "")
	if ruleID == "" {
		return errorResult("rule_id is required"), nil
	}

	ruleType := req.GetString("type", "")
	if ruleType == "" {
		return errorResult("type is required"), nil
	}
	if err := validateRuleType(ruleType); err != nil {
		return errorResult(err.Error()), nil
	}

	match := req.GetString("match", "")
	replace := req.GetString("replace", "")
	if match == "" && replace == "" {
		return errorResult("match or replace is required"), nil
	}

	log.Printf("mcp/proxy_rule_update: rule=%s", ruleID)

	rule, err := m.service.httpBackend.UpdateRule(ctx, ruleID, ProxyRuleInput{
		Label:   req.GetString("label", ""),
		Type:    ruleType,
		IsRegex: req.GetBool("is_regex", false),
		Match:   match,
		Replace: replace,
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("rule not found"), nil
		}
		if errors.Is(err, ErrLabelExists) {
			return errorResult("label already exists: " + err.Error()), nil
		}
		return errorResult("failed to update rule: " + err.Error()), nil
	}

	log.Printf("mcp/proxy_rule_update: updated rule %s", rule.RuleID)
	return jsonResult(rule)
}

func (m *mcpServer) handleProxyRuleDelete(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ruleID := req.GetString("rule_id", "")
	if ruleID == "" {
		return errorResult("rule_id is required"), nil
	}

	log.Printf("mcp/proxy_rule_delete: rule=%s", ruleID)

	if err := m.service.httpBackend.DeleteRule(ctx, ruleID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("rule not found"), nil
		}
		return errorResult("failed to delete rule: " + err.Error()), nil
	}

	log.Printf("mcp/proxy_rule_delete: deleted rule %s", ruleID)
	return jsonResult(RuleDeleteResponse{})
}

func (m *mcpServer) handleReplaySend(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	flowID := req.GetString("flow_id", "")
	if flowID == "" {
		return errorResult("flow_id is required"), nil
	}

	entry, ok := m.service.flowStore.Lookup(flowID)
	if !ok {
		return errorResult("flow_id not found: run proxy_list to see available flows"), nil
	}
	proxyEntries, err := m.service.httpBackend.GetProxyHistory(ctx, 1, entry.Offset)
	if err != nil {
		return errorResult("failed to fetch flow: " + err.Error()), nil
	}
	if len(proxyEntries) == 0 {
		return errorResult("flow not found in proxy history"), nil
	}
	rawRequest := []byte(proxyEntries[0].Request)

	rawRequest = modifyRequestLine(rawRequest, &PathQueryOpts{
		Path:        req.GetString("path", ""),
		Query:       req.GetString("query", ""),
		SetQuery:    req.GetStringSlice("set_query", nil),
		RemoveQuery: req.GetStringSlice("remove_query", nil),
	})

	headers, reqBody := splitHeadersBody(rawRequest)

	sendReq := &ReplaySendRequest{
		AddHeaders:    req.GetStringSlice("add_headers", nil),
		RemoveHeaders: req.GetStringSlice("remove_headers", nil),
		Target:        req.GetString("target", ""),
	}
	headers = applyHeaderModifications(headers, sendReq)

	if body := req.GetString("body", ""); body != "" {
		reqBody = []byte(body)
	}

	setJSON := req.GetStringSlice("set_json", nil)
	removeJSON := req.GetStringSlice("remove_json", nil)
	if len(setJSON) > 0 || len(removeJSON) > 0 {
		modifiedBody, err := modifyJSONBody(reqBody, setJSON, removeJSON)
		if err != nil {
			return errorResult("JSON body modification failed: " + err.Error()), nil
		}
		reqBody = modifiedBody
	}

	headers = updateContentLength(headers, len(reqBody))
	rawRequest = append(headers, reqBody...)

	if !req.GetBool("force", false) {
		issues := validateRequest(rawRequest)
		if slices.ContainsFunc(issues, func(i validationIssue) bool { return i.Severity == "error" }) {
			return errorResult("validation failed:\n" + formatIssues(issues)), nil
		}
	}

	host, port, usesHTTPS := parseTarget(rawRequest, req.GetString("target", ""))

	replayID := ids.Generate(ids.DefaultLength)

	scheme := schemeHTTP
	if usesHTTPS {
		scheme = schemeHTTPS
	}
	log.Printf("mcp/replay_send: %s sending to %s://%s:%d (flow=%s)", replayID, scheme, host, port, flowID)

	var timeout time.Duration
	if timeoutStr := req.GetString("timeout", ""); timeoutStr != "" {
		parsed, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return errorResult("invalid timeout duration: " + err.Error()), nil
		}
		timeout = parsed
	}

	sendInput := SendRequestInput{
		RawRequest: rawRequest,
		Target: Target{
			Hostname:  host,
			Port:      port,
			UsesHTTPS: usesHTTPS,
		},
		FollowRedirects: req.GetBool("follow_redirects", false),
		Timeout:         timeout,
	}

	result, err := m.service.httpBackend.SendRequest(ctx, "sectool-"+replayID, sendInput)
	if err != nil {
		return errorResult("request failed: " + err.Error()), nil
	}

	respHeaders := result.Headers
	respBody := result.Body
	respCode, respStatusLine := parseResponseStatus(respHeaders)
	log.Printf("mcp/replay_send: %s completed in %v (status=%d, size=%d)", replayID, result.Duration, respCode, len(respBody))

	m.service.requestStore.Store(replayID, &store.RequestEntry{
		Headers:  respHeaders,
		Body:     respBody,
		Duration: result.Duration,
	})

	return jsonResult(ReplaySendResponse{
		ReplayID: replayID,
		Duration: result.Duration.String(),
		ResponseDetails: ResponseDetails{
			Status:      respCode,
			StatusLine:  respStatusLine,
			RespHeaders: string(respHeaders),
			RespSize:    len(respBody),
			RespPreview: previewBody(respBody, responsePreviewSize),
		},
	})
}

func (m *mcpServer) handleReplayGet(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	replayID := req.GetString("replay_id", "")
	if replayID == "" {
		return errorResult("replay_id is required"), nil
	}

	log.Printf("mcp/replay_get: retrieving %s", replayID)
	result, ok := m.service.requestStore.Get(replayID)
	if !ok {
		return errorResult("replay not found: replay results are ephemeral and cleared on service restart"), nil
	}

	respCode, respStatusLine := parseResponseStatus(result.Headers)

	return jsonResult(ReplayGetResponse{
		ReplayID:    replayID,
		Duration:    result.Duration.String(),
		Status:      respCode,
		StatusLine:  respStatusLine,
		RespHeaders: string(result.Headers),
		RespBody:    base64.StdEncoding.EncodeToString(result.Body),
		RespSize:    len(result.Body),
	})
}

func (m *mcpServer) handleOastCreate(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	label := req.GetString("label", "")
	log.Printf("mcp/oast_create: creating new session (label=%q)", label)

	sess, err := m.service.oastBackend.CreateSession(ctx, label)
	if err != nil {
		return errorResult("failed to create OAST session: " + err.Error()), nil
	}

	log.Printf("mcp/oast_create: created session %s with domain %s (label=%q)", sess.ID, sess.Domain, sess.Label)
	return jsonResult(OastCreateResponse{
		OastID: sess.ID,
		Domain: sess.Domain,
		Label:  sess.Label,
	})
}

func (m *mcpServer) handleOastPoll(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	oastID := req.GetString("oast_id", "")
	if oastID == "" {
		return errorResult("oast_id is required"), nil
	}

	var wait time.Duration
	if waitStr := req.GetString("wait", ""); waitStr != "" {
		parsed, err := time.ParseDuration(waitStr)
		if err != nil {
			return errorResult("invalid wait duration: " + err.Error()), nil
		}
		if parsed > 120*time.Second {
			parsed = 120 * time.Second
		}
		wait = parsed
	}

	since := req.GetString("since", "")
	limit := req.GetInt("limit", 0)

	log.Printf("mcp/oast_poll: polling session %s (wait=%v since=%q limit=%d)", oastID, wait, since, limit)

	result, err := m.service.oastBackend.PollSession(ctx, oastID, since, wait, limit)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("session not found"), nil
		}
		return errorResult("failed to poll session: " + err.Error()), nil
	}

	events := make([]OastEvent, len(result.Events))
	for i, e := range result.Events {
		events[i] = OastEvent{
			EventID:   e.ID,
			Time:      e.Time.UTC().Format(time.RFC3339),
			Type:      e.Type,
			SourceIP:  e.SourceIP,
			Subdomain: e.Subdomain,
			Details:   e.Details,
		}
	}

	log.Printf("mcp/oast_poll: session %s returned %d events", oastID, len(events))
	return jsonResult(OastPollResponse{
		Events:       events,
		DroppedCount: result.DroppedCount,
	})
}

func (m *mcpServer) handleOastGet(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	oastID := req.GetString("oast_id", "")
	if oastID == "" {
		return errorResult("oast_id is required"), nil
	}
	eventID := req.GetString("event_id", "")
	if eventID == "" {
		return errorResult("event_id is required"), nil
	}

	log.Printf("mcp/oast_get: getting event %s from session %s", eventID, oastID)

	event, err := m.service.oastBackend.GetEvent(ctx, oastID, eventID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("session or event not found"), nil
		}
		return errorResult("failed to get event: " + err.Error()), nil
	}

	log.Printf("mcp/oast_get: returning event %s", eventID)
	return jsonResult(OastGetResponse{
		EventID:   event.ID,
		Time:      event.Time.UTC().Format(time.RFC3339),
		Type:      event.Type,
		SourceIP:  event.SourceIP,
		Subdomain: event.Subdomain,
		Details:   event.Details,
	})
}

func (m *mcpServer) handleOastList(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	limit := req.GetInt("limit", 0)

	resp, err := m.service.processOastList(ctx, limit)
	if err != nil {
		return errorResult("failed to list OAST sessions: " + err.Error()), nil
	}

	return jsonResult(resp)
}

func (m *mcpServer) handleOastDelete(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	oastID := req.GetString("oast_id", "")
	if oastID == "" {
		return errorResult("oast_id is required"), nil
	}

	log.Printf("mcp/oast_delete: deleting session %s", oastID)

	if err := m.service.oastBackend.DeleteSession(ctx, oastID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return errorResult("session not found"), nil
		}
		return errorResult("failed to delete session: " + err.Error()), nil
	}

	return jsonResult(OastDeleteResponse{})
}

func (m *mcpServer) handleEncodeURL(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	decode := req.GetBool("decode", false)

	var result string
	if decode {
		decoded, err := url.QueryUnescape(input)
		if err != nil {
			return errorResult("URL decode error: " + err.Error()), nil
		}
		result = decoded
	} else {
		result = url.QueryEscape(input)
	}

	return mcp.NewToolResultText(result), nil
}

func (m *mcpServer) handleEncodeBase64(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	decode := req.GetBool("decode", false)

	var result string
	if decode {
		decoded, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return errorResult("base64 decode error: " + err.Error()), nil
		}
		result = string(decoded)
	} else {
		result = base64.StdEncoding.EncodeToString([]byte(input))
	}

	return mcp.NewToolResultText(result), nil
}

func (m *mcpServer) handleEncodeHTML(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input := req.GetString("input", "")
	if input == "" {
		return errorResult("input is required"), nil
	}

	decode := req.GetBool("decode", false)

	var result string
	if decode {
		result = html.UnescapeString(input)
	} else {
		result = html.EscapeString(input)
	}

	return mcp.NewToolResultText(result), nil
}

func jsonResult(data interface{}) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return errorResult("failed to marshal response: " + err.Error()), nil
	}
	return mcp.NewToolResultText(string(b)), nil
}

func errorResult(message string) *mcp.CallToolResult {
	return mcp.NewToolResultError(message)
}
