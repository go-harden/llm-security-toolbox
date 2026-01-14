package service

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/pflag"

	"github.com/jentfoo/llm-security-toolbox/sectool/cli"
	"github.com/jentfoo/llm-security-toolbox/sectool/config"
)

const DefaultMCPPort = 9119

// Workflow mode constants
const (
	WorkflowModeNone       = "none"
	WorkflowModeExplore    = "explore"
	WorkflowModeTestReport = "test-report"
)

type DaemonFlags struct {
	WorkDir      string
	BurpMCPURL   string
	MCP          bool
	MCPPort      int
	WorkflowMode string // "", "none", "explore", "test-report"
}

func ParseDaemonFlags(args []string) (DaemonFlags, error) {
	fs := pflag.NewFlagSet("service", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	flags := DaemonFlags{
		BurpMCPURL: config.DefaultBurpMCPURL,
		MCPPort:    DefaultMCPPort,
	}

	// serviceFlag is parsed but unused; defined so pflag accepts --service when --mcp is also passed
	var serviceFlag bool
	fs.BoolVar(&serviceFlag, "service", false, "")
	_ = serviceFlag
	fs.StringVar(&flags.WorkDir, "workdir", "", "working directory for service state")
	fs.StringVar(&flags.BurpMCPURL, "burp-mcp-url", flags.BurpMCPURL, "Burp MCP SSE endpoint URL")
	fs.BoolVar(&flags.MCP, "mcp", false, "enable MCP SSE server")
	fs.IntVar(&flags.MCPPort, "mcp-port", flags.MCPPort, "MCP SSE server port")
	fs.StringVar(&flags.WorkflowMode, "workflow", "", "MCP workflow mode: none, explore, test-report")

	if err := fs.Parse(args); err != nil {
		return flags, err
	}

	// Validate --workflow requires --mcp
	if flags.WorkflowMode != "" && !flags.MCP {
		return flags, errors.New("--workflow requires --mcp")
	}

	// Validate workflow mode value
	switch flags.WorkflowMode {
	case "", WorkflowModeNone, WorkflowModeExplore, WorkflowModeTestReport:
		// Valid
	default:
		return flags, fmt.Errorf("invalid --workflow value %q: must be none, explore, or test-report", flags.WorkflowMode)
	}

	return flags, nil
}

var serviceSubcommands = []string{"status", "stop", "logs", "help"}

func Parse(args []string) error {
	if len(args) < 1 {
		printUsage()
		return errors.New("subcommand required")
	}

	switch args[0] {
	case "status":
		return parseStatus(args[1:])
	case "stop":
		return parseStop(args[1:])
	case "logs":
		return parseLogs(args[1:])
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return cli.UnknownSubcommandError("service", args[0], serviceSubcommands)
	}
}

func printUsage() {
	fmt.Fprint(os.Stderr, `Usage: sectool service <command> [options]

Manage the sectool background service. The service auto-starts when needed;
these commands are for debugging and manual control.

Commands:
  status     Show service health and backend connection status
  stop       Gracefully stop the running service
  logs       View service logs (useful for debugging backend errors)

---

service logs [options]
  -n, --lines <num>      number of lines to show (default: 50)
  -f, --follow           follow log output continuously

---

MCP Server Mode:

To start the service with MCP support for Claude Code or Codex integration:

  sectool --mcp [--mcp-port PORT] [--workflow MODE]

This starts both the CLI service and an MCP SSE server. Configuration
instructions for Claude Code and Codex will be printed on startup.

Options:
  --mcp                  Enable MCP SSE server
  --mcp-port PORT        MCP server port (default: 9119)
  --workflow MODE        Set workflow mode (requires --mcp):
                           (default)     Require workflow tool call first
                           none          No workflow, all tools available
                           explore       Exploration instructions, all tools
                           test-report   Validation instructions, no crawl tools
`)
}

func parseStatus(args []string) error {
	fs := pflag.NewFlagSet("service status", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool service status [options]

Show service status and health.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return status(timeout)
}

func parseStop(args []string) error {
	fs := pflag.NewFlagSet("service stop", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool service stop [options]

Stop the running service.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return stop(timeout)
}

func parseLogs(args []string) error {
	fs := pflag.NewFlagSet("service logs", pflag.ContinueOnError)
	fs.SetInterspersed(true)
	var timeout time.Duration
	var follow bool
	var lines int

	fs.DurationVar(&timeout, "timeout", 30*time.Second, "client-side timeout")
	fs.BoolVarP(&follow, "follow", "f", false, "follow log output")
	fs.IntVarP(&lines, "lines", "n", 50, "number of lines to show")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sectool service logs [options]

View service logs.

Options:
`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return err
	}

	return logs(timeout, follow, lines)
}
