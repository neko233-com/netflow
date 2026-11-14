// Command netflow-agent exposes the running desktop app to MCP clients and CLI users.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/neko233-com/netflow"
	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/appdir"
	"github.com/neko233-com/netflow/internal/backup"
	"github.com/neko233-com/netflow/internal/migration"
)

func run(args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("netflow-agent", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.Usage = func() {
		fmt.Fprintln(output, "netflow-agent [--config-dir PATH] [--pid PID] <command>\nCommands: serve [--tun=false], shutdown, version, status, diagnostics, update-geo, tun on|off, profiles, import-profile, update-profile ID, delete-profile ID, profile-job-status ID, groups, providers, update-provider KIND NAME, provider-job-status ID, rules [OFFSET [LIMIT]], select GROUP NODE, mode MODE, use-profile ID, close-connection ID, preview, apply ID, mcp, migrate-preview PATH, migrate-import PATH, migrate-export PATH, backup-create PATH, restore-create ARCHIVE DIRECTORY, backup-job-status ID, backup-schedule, backup-schedule-set off|on DIRECTORY HOURS, backup-export PATH, backup-restore PATH")
	}
	dir := flags.String("config-dir", "", "absolute NetFlow config directory")
	pid := flags.Int("pid", 0, "NetFlow process id when several instances run")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.Arg(0) == "version" {
		if flags.NArg() != 1 {
			return errors.New("version takes no arguments")
		}
		return json.NewEncoder(output).Encode(struct {
			Version string `json:"version"`
		}{Version: netflow.Version()})
	}
	if *dir == "" {
		var err error
		*dir, err = (appdir.Default{}).ConfigDir()
		if err != nil {
			return err
		}
	}
	if !filepath.IsAbs(*dir) {
		return fmt.Errorf("config-dir must be an absolute path")
	}
	client := agent.Client{Dir: *dir, PID: *pid}
	if flags.NArg() == 0 {
		return fmt.Errorf("usage: netflow-agent [--config-dir PATH] [--pid PID] mcp|status|preview|apply|migrate-preview|migrate-import|migrate-export")
	}
	ctx := context.Background()
	switch flags.Arg(0) {
	case "serve":
		if *pid != 0 {
			return errors.New("--pid is not applicable to serve")
		}
		return runServe(*dir, flags.Args()[1:], output)
	case "backup-export", "backup-restore":
		if flags.NArg() != 2 || *pid != 0 || !filepath.IsAbs(flags.Arg(1)) {
			return errors.New("backup command requires an absolute archive path; --pid is not applicable")
		}
		var result backup.Manifest
		var err error
		if flags.Arg(0) == "backup-export" {
			info, statErr := os.Stat(*dir)
			if statErr != nil || !info.IsDir() {
				return errors.New("configuration directory does not exist")
			}
			lock, lockErr := appdir.Acquire(*dir)
			if lockErr != nil {
				return lockErr
			}
			defer lock.Close()
			result, err = backup.Export(*dir, flags.Arg(1))
		} else {
			result, err = backup.Restore(flags.Arg(1), *dir)
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(result)
	case "migrate-export":
		if flags.NArg() != 2 || *pid != 0 {
			return errors.New("migrate-export requires an absolute destination ZIP path; --pid is not applicable")
		}
		if !filepath.IsAbs(flags.Arg(1)) {
			return errors.New("destination must be an absolute path")
		}
		lock, err := appdir.Acquire(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		result, err := migration.ExportVerge(*dir, flags.Arg(1))
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(result)
	case "help":
		flags.Usage()
		return nil
	case "diagnostics", "shutdown", "update-geo", "groups", "profiles", "import-profile", "update-profile", "delete-profile", "profile-job-status", "backup-create", "restore-create", "backup-job-status", "backup-schedule", "backup-schedule-set", "providers", "update-provider", "provider-job-status", "rules", "select", "mode", "use-profile", "close-connection", "tun":
		method := flags.Arg(0)
		stdin := input
		var input any
		switch method {
		case "diagnostics", "shutdown", "update-geo", "groups", "profiles", "providers", "backup-schedule":
			if flags.NArg() != 1 {
				return fmt.Errorf("%s takes no arguments", method)
			}
		case "rules":
			if flags.NArg() > 3 {
				return errors.New("rules takes optional OFFSET and LIMIT")
			}
			q := agent.RulesArgs{}
			var err error
			if flags.NArg() > 1 {
				q.Offset, err = strconv.Atoi(flags.Arg(1))
				if err != nil {
					return errors.New("invalid rules offset")
				}
			}
			if flags.NArg() > 2 {
				q.Limit, err = strconv.Atoi(flags.Arg(2))
				if err != nil {
					return errors.New("invalid rules limit")
				}
			}
			input = q
		case "update-provider":
			if flags.NArg() != 3 || (flags.Arg(1) != "proxy" && flags.Arg(1) != "rule") || flags.Arg(2) == "" {
				return errors.New("update-provider requires proxy|rule and a provider name")
			}
			input = agent.ProviderUpdateArgs{Kind: flags.Arg(1), Name: flags.Arg(2)}
		case "provider-job-status":
			if flags.NArg() != 2 || flags.Arg(1) == "" {
				return errors.New("provider-job-status requires a job ID")
			}
			input = agent.ProviderJobArgs{JobID: flags.Arg(1)}
		case "profile-job-status":
			if flags.NArg() != 2 || flags.Arg(1) == "" {
				return errors.New("profile-job-status requires a job ID")
			}
			input = agent.ProfileJobArgs{JobID: flags.Arg(1)}
		case "backup-schedule-set":
			if flags.NArg() == 2 && flags.Arg(1) == "off" {
				input = agent.BackupScheduleArgs{}
			} else if flags.NArg() == 4 && flags.Arg(1) == "on" && filepath.IsAbs(flags.Arg(2)) {
				hours, err := strconv.Atoi(flags.Arg(3))
				if err != nil || hours < 1 || hours > 168 {
					return errors.New("backup schedule interval must be 1 to 168 hours")
				}
				input = agent.BackupScheduleArgs{Enabled: true, Directory: flags.Arg(2), IntervalHours: hours}
			} else {
				return errors.New("backup-schedule-set requires off or on DIRECTORY HOURS")
			}
		case "backup-create":
			if flags.NArg() != 2 || !filepath.IsAbs(flags.Arg(1)) {
				return errors.New("backup-create requires an absolute destination path")
			}
			input = agent.BackupArgs{Path: flags.Arg(1)}
		case "backup-job-status":
			if flags.NArg() != 2 || flags.Arg(1) == "" {
				return errors.New("backup-job-status requires a job ID")
			}
			input = agent.BackupJobArgs{JobID: flags.Arg(1)}
		case "restore-create":
			if flags.NArg() != 3 || !filepath.IsAbs(flags.Arg(1)) || !filepath.IsAbs(flags.Arg(2)) {
				return errors.New("restore-create requires absolute archive and new directory paths")
			}
			input = agent.RestoreArgs{Archive: flags.Arg(1), Destination: flags.Arg(2)}
		case "import-profile":
			if flags.NArg() != 1 {
				return errors.New("import-profile reads one JSON object from stdin")
			}
			body, err := io.ReadAll(io.LimitReader(stdin, (1<<20)+1))
			if err != nil || len(body) > 1<<20 {
				return errors.New("invalid or oversized profile input")
			}
			var value agent.ProfileImportArgs
			dec := json.NewDecoder(bytes.NewReader(body))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&value); err != nil {
				return err
			}
			var extra any
			if dec.Decode(&extra) != io.EOF {
				return errors.New("unexpected trailing JSON")
			}
			input = value
		case "select":
			if flags.NArg() != 3 {
				return errors.New("select requires GROUP and NODE")
			}
			input = agent.SelectArgs{Group: flags.Arg(1), Node: flags.Arg(2)}
		case "tun":
			if flags.NArg() != 2 || (flags.Arg(1) != "on" && flags.Arg(1) != "off") {
				return errors.New("tun requires on or off")
			}
			enabled := flags.Arg(1) == "on"
			input = agent.TunArgs{Enabled: &enabled}
		case "mode":
			if flags.NArg() != 2 {
				return errors.New("mode requires rule, global, or direct")
			}
			input = agent.ModeArgs{Mode: flags.Arg(1)}
		case "use-profile", "update-profile", "delete-profile":
			if flags.NArg() != 2 {
				return fmt.Errorf("%s requires a profile ID", method)
			}
			input = agent.ProfileArgs{ProfileID: flags.Arg(1)}
		case "close-connection":
			if flags.NArg() != 2 {
				return errors.New("close-connection requires a connection ID")
			}
			input = agent.ConnectionArgs{ConnectionID: flags.Arg(1)}
		}
		var out json.RawMessage
		if err := client.Call(ctx, method, input, &out); err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(out)
	case "migrate-preview", "migrate-import":
		if flags.NArg() != 2 || *pid != 0 {
			return fmt.Errorf("%s requires a Verge directory or ZIP; --pid is not applicable", flags.Arg(0))
		}
		source, err := migration.ReadVerge(flags.Arg(1))
		if err != nil {
			return err
		}
		if flags.Arg(0) == "migrate-preview" {
			return json.NewEncoder(output).Encode(source.Preview())
		}
		if err := source.ValidateTarget(*dir); err != nil {
			return err
		}
		lock, err := appdir.Acquire(*dir)
		if err != nil {
			return err
		}
		defer lock.Close()
		result, err := source.ImportVerge(*dir)
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(result)
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
		body, err := io.ReadAll(io.LimitReader(input, (1<<20)+1))
		if err != nil {
			return err
		}
		if len(body) > 1<<20 {
			return errors.New("input exceeds 1 MiB")
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&change); err != nil {
			return err
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return errors.New("unexpected trailing JSON")
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
