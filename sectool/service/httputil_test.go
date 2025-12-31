package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadResponseStatusCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected int
	}{
		{
			name:     "http_1_1_200",
			input:    []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"),
			expected: 200,
		},
		{
			name:     "http_1_0_404",
			input:    []byte("HTTP/1.0 404 Not Found\r\n\r\n"),
			expected: 404,
		},
		{
			name:     "http_2_200",
			input:    []byte("HTTP/2 200\r\nContent-Type: application/json\r\n\r\n{}"),
			expected: 200,
		},
		{
			name:     "http_2_0_500",
			input:    []byte("HTTP/2.0 500 Internal Server Error\r\n\r\n"),
			expected: 500,
		},
		{
			name:     "status_204_no_content",
			input:    []byte("HTTP/1.1 204 No Content\r\n\r\n"),
			expected: 204,
		},
		{
			name:     "status_301_redirect",
			input:    []byte("HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\n\r\n"),
			expected: 301,
		},
		{
			name:     "lf_only_line_ending",
			input:    []byte("HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>"),
			expected: 200,
		},
		{
			name:     "binary_body_after_headers",
			input:    append([]byte("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n"), []byte{0x89, 0x50, 0x4E, 0x47}...),
			expected: 200,
		},
		{
			name:     "truncated_after_status_line",
			input:    []byte("HTTP/1.1 200 OK\r\n"),
			expected: 200,
		},
		{
			name:     "status_only_no_reason",
			input:    []byte("HTTP/1.1 200\r\n\r\n"),
			expected: 200,
		},
		{
			name:     "empty_input",
			input:    []byte{},
			expected: 0,
		},
		{
			name:     "no_http_prefix",
			input:    []byte("GET / HTTP/1.1\r\n"),
			expected: 0,
		},
		{
			name:     "malformed_no_space",
			input:    []byte("HTTP/1.1200OK\r\n"),
			expected: 0,
		},
		{
			name:     "invalid_status_code_letters",
			input:    []byte("HTTP/1.1 ABC OK\r\n"),
			expected: 0,
		},
		{
			name:     "status_code_too_low",
			input:    []byte("HTTP/1.1 99 Too Low\r\n"),
			expected: 0,
		},
		{
			name:     "status_code_too_high",
			input:    []byte("HTTP/1.1 600 Too High\r\n"),
			expected: 0,
		},
		{
			name:     "partial_status_code",
			input:    []byte("HTTP/1.1 20"),
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, readResponseStatusCode(tc.input))
		})
	}
}

func TestTransformRequestForValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "http_2_to_http_1_1",
			input:    []byte("POST /api/example HTTP/2\r\nHost: example.com\r\n\r\n"),
			expected: []byte("POST /api/example HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "get_http_2",
			input:    []byte("GET /path HTTP/2\r\nHost: test.com\r\n\r\n"),
			expected: []byte("GET /path HTTP/1.1\r\nHost: test.com\r\n\r\n"),
		},
		{
			name:     "http_1_1_unchanged",
			input:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			expected: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "http_1_0_unchanged",
			input:    []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"),
			expected: []byte("GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"),
		},
		{
			name:     "http_2_with_body",
			input:    []byte("POST /api HTTP/2\r\nHost: test.com\r\nContent-Length: 4\r\n\r\ntest"),
			expected: []byte("POST /api HTTP/1.1\r\nHost: test.com\r\nContent-Length: 4\r\n\r\ntest"),
		},
		{
			name:     "no_crlf",
			input:    []byte("GET / HTTP/2"),
			expected: []byte("GET / HTTP/2"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := transformRequestForValidation(tc.input)
			require.Equal(t, string(tc.expected), string(result))
		})
	}
}

func TestParseRequestLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		line        string
		wantMethod  string
		wantPath    string
		wantQuery   string
		wantVersion string
	}{
		{
			name:        "simple_get",
			line:        "GET /api/users HTTP/1.1",
			wantMethod:  "GET",
			wantPath:    "/api/users",
			wantQuery:   "",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "get_with_query",
			line:        "GET /api/users?id=123&role=admin HTTP/1.1",
			wantMethod:  "GET",
			wantPath:    "/api/users",
			wantQuery:   "id=123&role=admin",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "post_http_2",
			line:        "POST /api/data HTTP/2",
			wantMethod:  "POST",
			wantPath:    "/api/data",
			wantQuery:   "",
			wantVersion: "HTTP/2",
		},
		{
			name:        "root_path",
			line:        "GET / HTTP/1.1",
			wantMethod:  "GET",
			wantPath:    "/",
			wantQuery:   "",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "empty_query_value",
			line:        "GET /search?q= HTTP/1.1",
			wantMethod:  "GET",
			wantPath:    "/search",
			wantQuery:   "q=",
			wantVersion: "HTTP/1.1",
		},
		{
			name:        "empty_input",
			line:        "",
			wantMethod:  "",
			wantPath:    "",
			wantQuery:   "",
			wantVersion: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			method, path, query, version := parseRequestLine(tc.line)
			assert.Equal(t, tc.wantMethod, method)
			assert.Equal(t, tc.wantPath, path)
			assert.Equal(t, tc.wantQuery, query)
			assert.Equal(t, tc.wantVersion, version)
		})
	}
}

func TestModifyRequestLine(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		opts     *PathQueryOpts
		expected string
	}{
		{
			name:     "nil_opts",
			input:    []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     nil,
			expected: "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "empty_opts",
			input:    []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{},
			expected: "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "replace_path",
			input:    []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{Path: "/api/v2/accounts"},
			expected: "GET /api/v2/accounts HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "replace_path_preserves_query",
			input:    []byte("GET /api/users?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{Path: "/api/v2/accounts"},
			expected: "GET /api/v2/accounts?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "replace_query",
			input:    []byte("GET /api/users?old=value HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{Query: "new=param&foo=bar"},
			expected: "GET /api/users?new=param&foo=bar HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "add_query_to_path_without_query",
			input:    []byte("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{Query: "id=123"},
			expected: "GET /api/users?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "set_query_param",
			input:    []byte("GET /api/users?id=123&role=user HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{SetQuery: []string{"role=admin"}},
			expected: "GET /api/users?id=123&role=admin HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "remove_query_param",
			input:    []byte("GET /api/users?id=123&secret=abc HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{RemoveQuery: []string{"secret"}},
			expected: "GET /api/users?id=123 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:  "combined_operations",
			input: []byte("GET /old/path?a=1&b=2&c=3 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			opts: &PathQueryOpts{
				Path:        "/new/path",
				RemoveQuery: []string{"b"},
				SetQuery:    []string{"a=changed", "d=4"},
			},
			expected: "GET /new/path?a=changed&c=3&d=4 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		},
		{
			name:     "preserves_body",
			input:    []byte("POST /api/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest"),
			opts:     &PathQueryOpts{Path: "/api/v2/data"},
			expected: "POST /api/v2/data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest",
		},
		{
			name:     "http_2_version_preserved",
			input:    []byte("GET /api/test HTTP/2\r\nHost: example.com\r\n\r\n"),
			opts:     &PathQueryOpts{Path: "/api/v2/test"},
			expected: "GET /api/v2/test HTTP/2\r\nHost: example.com\r\n\r\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := modifyRequestLine(tc.input, tc.opts)
			assert.Equal(t, tc.expected, string(result))
		})
	}
}

func TestPathQueryOptsHasModifications(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		opts     PathQueryOpts
		expected bool
	}{
		{
			name:     "empty",
			opts:     PathQueryOpts{},
			expected: false,
		},
		{
			name:     "path_set",
			opts:     PathQueryOpts{Path: "/new"},
			expected: true,
		},
		{
			name:     "query_set",
			opts:     PathQueryOpts{Query: "a=1"},
			expected: true,
		},
		{
			name:     "set_query_set",
			opts:     PathQueryOpts{SetQuery: []string{"a=1"}},
			expected: true,
		},
		{
			name:     "remove_query_set",
			opts:     PathQueryOpts{RemoveQuery: []string{"a"}},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.opts.HasModifications())
		})
	}
}

func TestParseResponseStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          []byte
		expectedCode   int
		expectedStatus string
	}{
		{
			name:           "http_1_1_200",
			input:          []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"),
			expectedCode:   200,
			expectedStatus: "HTTP/1.1 200 OK",
		},
		{
			name:           "http_1_0_404",
			input:          []byte("HTTP/1.0 404 Not Found\r\n\r\n"),
			expectedCode:   404,
			expectedStatus: "HTTP/1.0 404 Not Found",
		},
		{
			name:           "http_1_1_500",
			input:          []byte("HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nerror"),
			expectedCode:   500,
			expectedStatus: "HTTP/1.1 500 Internal Server Error",
		},
		{
			name:           "http_1_1_301_redirect",
			input:          []byte("HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\n\r\n"),
			expectedCode:   301,
			expectedStatus: "HTTP/1.1 301 Moved Permanently",
		},
		{
			name:           "http_1_1_204_no_content",
			input:          []byte("HTTP/1.1 204 No Content\r\n\r\n"),
			expectedCode:   204,
			expectedStatus: "HTTP/1.1 204 No Content",
		},
		{
			name:           "empty_input",
			input:          []byte{},
			expectedCode:   0,
			expectedStatus: "",
		},
		{
			name:           "malformed_response",
			input:          []byte("not an http response"),
			expectedCode:   0,
			expectedStatus: "",
		},
		{
			name:           "truncated_status",
			input:          []byte("HTTP/1.1"),
			expectedCode:   0,
			expectedStatus: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, statusLine := parseResponseStatus(tc.input)
			assert.Equal(t, tc.expectedCode, code)
			assert.Equal(t, tc.expectedStatus, statusLine)
		})
	}
}
