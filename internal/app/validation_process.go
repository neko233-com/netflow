package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/neko233-com/netflow/internal/validation"
)

var validationExecutablePath = os.Executable
var validationSlots = make(chan struct{}, 1)

func validateConfigurations(parent context.Context, dir string, configs []validation.Config) (validation.Result, error) {
	var result validation.Result
	ctx, cancel := context.WithTimeout(parent, 25*time.Second)
	defer cancel()
	select {
	case validationSlots <- struct{}{}:
		defer func() { <-validationSlots }()
	case <-ctx.Done():
		return result, errors.New("offline configuration validation canceled or timed out")
	}
	if len(configs) == 0 {
		return result, errors.New("no configurations to validate")
	}
	request, err := json.Marshal(validation.Request{Directory: dir, Configs: configs})
	if err != nil {
		return result, err
	}
	if len(request) > validation.MaxRequest {
		return result, errors.New("validation request exceeds size limit")
	}
	exe, err := validationExecutablePath()
	if err != nil {
		return result, err
	}
	cmd := exec.CommandContext(ctx, exe, "--internal-validate")
	configureValidationProcess(cmd)
	cmd.Stdin = bytes.NewReader(request)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return result, errors.New("offline configuration validation canceled or timed out")
		}
		if stderr.Len() == 0 {
			return result, fmt.Errorf("offline configuration validation could not run: %w", err)
		}
		return result, fmt.Errorf("offline configuration validation failed: %s", stderr.String())
	}
	if stdout.Len() > validation.MaxRequest {
		return result, errors.New("validation response exceeds size limit")
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Sources == nil {
		return validation.Result{}, errors.New("invalid offline validation response")
	}
	return result, nil
}
