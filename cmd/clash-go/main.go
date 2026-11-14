// Command clash-go is the Clash Go desktop app.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/neko233-com/netflow/internal/app"
	"github.com/neko233-com/netflow/internal/core"
	"github.com/neko233-com/netflow/internal/validation"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--internal-validate" {
		if err := validation.Serve(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--headless" {
		if err := runHeadless(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := app.New(app.Options{}).Run(); err != nil {
		log.Fatal(err)
	}
}

func runHeadless(args []string) error {
	flags := flag.NewFlagSet("NetFlow --headless", flag.ContinueOnError)
	tun := flags.Bool("tun", true, "enable TUN at startup")
	recovery := flags.Bool("recovery", false, "allow a stopped core for configuration recovery")
	parentStdin := flags.Bool("parent-stdin", false, "stop when the controlling CLI closes its pipe")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected headless arguments")
	}
	if *recovery && *tun {
		return fmt.Errorf("recovery requires --tun=false")
	}
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if *parentStdin {
		go func() {
			_, _ = io.Copy(io.Discard, os.Stdin)
			cancel()
		}()
	}
	return app.New(app.Options{}).RunHeadless(ctx, app.HeadlessOptions{
		EnableTUN:    *tun,
		AllowStopped: *recovery,
		ReadyStatus: func(status core.Status) {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ready": true, "headless": true, "tun": status.TUN, "core_running": status.Running, "recovery": *recovery})
		},
	})
}
