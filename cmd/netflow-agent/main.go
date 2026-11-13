// Command netflow-agent exposes the running desktop app to MCP clients and CLI users.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appdir"
)

func run(args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("netflow-agent", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dir := flags.String("config-dir", "", "absolute NetFlow config directory")
	pid := flags.Int("pid", 0, "NetFlow process id when several instances run")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		var err error
		*dir, err = (appdir.Default{}).ConfigDir()
		if err != nil {
			return err
		}
	}
	client := agent.Client{Dir: *dir, PID: *pid}
	if flags.NArg() == 0 {
		return fmt.Errorf("usage: netflow-agent [--config-dir PATH] [--pid PID] mcp|status|preview|apply")
	}
	ctx := context.Background()
	switch flags.Arg(0) {
	case "mcp":
		if flags.NArg() != 1 {
			return fmt.Errorf("mcp takes no additional arguments")
		}
		return agent.ServeMCP(ctx, client)
	case "status":
		if flags.NArg() != 1 {
			return fmt.Errorf("status takes no additional arguments")
		}
		var out agent.Status
		if err := client.Call(ctx, "status", nil, &out); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(out)
	case "preview":
		if flags.NArg() != 1 {
			return fmt.Errorf("preview reads one JSON object from stdin")
		}
		var change agent.Change
		dec := json.NewDecoder(io.LimitReader(input, (1<<20)+1))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&change); err != nil {
			return err
		}
		var out agent.Preview
		if err := client.Call(ctx, "preview", change, &out); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(out)
	case "apply":
		if flags.NArg() != 2 {
			return fmt.Errorf("apply requires the proposal id")
		}
		var out agent.ApplyResult
		if err := client.Call(ctx, "apply", agent.ApplyArgs{ProposalID: flags.Arg(1)}, &out); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(out)
	default:
		return fmt.Errorf("unknown command %q", flags.Arg(0))
	}
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
