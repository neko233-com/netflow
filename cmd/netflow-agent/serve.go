package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"
)

func runServe(dir string, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(output)
	tun := flags.Bool("tun", true, "enable TUN at startup")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("serve accepts only --tun=true or --tun=false")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	var appExe string
	switch runtime.GOOS {
	case "windows":
		appExe = filepath.Join(filepath.Dir(exe), "NetFlow.exe")
	case "darwin":
		appExe = filepath.Join(filepath.Dir(exe), "..", "MacOS", "NetFlow")
	default:
		appExe = filepath.Join(filepath.Dir(exe), "NetFlow")
	}
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		return err
	}
	defer writePipe.Close()
	cmd := exec.Command(appExe, "--headless", "--tun="+strconv.FormatBool(*tun), "--parent-stdin")
	cmd.Env = append(os.Environ(), "NETFLOW_CONFIG_DIR="+dir)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = readPipe, output, os.Stderr
	configureHeadlessProcess(cmd)
	if err := cmd.Start(); err != nil {
		_ = readPipe.Close()
		return fmt.Errorf("start headless NetFlow: %w", err)
	}
	_ = readPipe.Close()
	finished := make(chan error, 1)
	go func() { finished <- cmd.Wait() }()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	select {
	case err := <-finished:
		return err
	case <-ctx.Done():
		// Closing the pipe asks the child to stop the kernel and restore routes.
		// Do not kill it on timeout: it may still be completing that cleanup.
		_ = writePipe.Close()
		select {
		case err := <-finished:
			return err
		case <-time.After(45 * time.Second):
			return errors.New("headless shutdown is still in progress")
		}
	}
}
