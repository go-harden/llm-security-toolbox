# llm-security-toolbox

An LLM-first CLI tool that enables coding agents to collaborate with you on security testing tasks. By providing common functionality for web application and API testing, sectool lets you brainstorm with an agent, validate security reports together, or have the agent probe vulnerabilities in parallel with your own testing.

## Getting Started

### 1. Install sectool

Download the binary for your platform from the [latest release](https://github.com/jentfoo/llm-security-toolbox/releases), or build from source:

```bash
git clone https://github.com/jentfoo/llm-security-toolbox.git
cd llm-security-toolbox
make build
```

### 2. Set up Burp Suite with MCP

Install [Burp Suite Community](https://portswigger.net/burp/communitydownload) and add the MCP extension from the BApp Store.

Start Burp and ensure the MCP server is running on `http://127.0.0.1:9876/sse`. It's best if your burp session starts fresh without a proxy history for when starting with your agent.

> Note: Burp MCP is currently required. A built-in proxy is planned for future releases ([#3](https://github.com/jentfoo/llm-security-toolbox/issues/3)).

### 3. Initialize your working directory

Run `sectool init` with your testing mode:

```bash
sectool init test-report   # Validate a known security report
sectool init explore       # Broader exploratory security testing
```

This creates a `.sectool/` directory with agent system prompts tailored to your task.

### 4. Start your agent

The init command outputs instructions for starting agents with the generated system prompt. For example:

```bash
claude --system-prompt-file .sectool/AGENT-explore.md
```

### 5. Provide context in your first prompt

Give the agent the information it needs to start:
- For `test-report`: Include the security report or vulnerability details to validate
- For `explore`: Describe the target application and testing scope

### 6. Collaborate on the testing

Work with the agent to build a test plan and execute it together. The agent can query proxy history, replay modified requests, and test for out-of-band interactions while you handle browser-based actions like authentication.

## Key Features

- **Proxy history access** - Query and filter HTTP traffic captured through Burp Suite
- **Request export and replay** - Export requests to disk, edit them, and replay with modifications
- **OAST testing** - Create out-of-band domains and poll for DNS/HTTP/SMTP interactions via Interactsh
- **Encoding utilities** - URL, Base64, and HTML entity encoding/decoding
- **LLM-optimized** - CLI interactions optimized for agent usage
