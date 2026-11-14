package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/neko233-com/netflow/internal/agent"
)

func TestDelayCLIReadsTypedJSONAndPollsJob(t *testing.T) {
	dir := t.TempDir()
	bridge, err := agent.Start(dir, func(_ context.Context, method string, raw json.RawMessage) (any, error) {
		switch method {
		case "delay-test":
			var in agent.DelayArgs
			if json.Unmarshal(raw, &in) != nil || in.Group != "group" || in.Node != "node" || in.URL != "https://example.test/?token=synthetic-secret" {
				return nil, errors.New("bad input")
			}
			return agent.DelayJob{JobID: "job", State: "pending"}, nil
		case "delay-job-status":
			var in agent.DelayJobArgs
			if json.Unmarshal(raw, &in) != nil || in.JobID != "job" {
				return nil, errors.New("bad job")
			}
			return agent.DelayJob{JobID: "job", State: "succeeded", DelayMS: 42}, nil
		default:
			return nil, errors.New("unknown method")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	var output bytes.Buffer
	input := `{"group":"group","node":"node","url":"https://example.test/?token=synthetic-secret"}`
	if err := run([]string{"--config-dir", dir, "delay-test"}, strings.NewReader(input), &output); err != nil || strings.Contains(output.String(), "synthetic-secret") {
		t.Fatalf("start: %s %v", output.String(), err)
	}
	output.Reset()
	if err := run([]string{"--config-dir", dir, "delay-job-status", "job"}, strings.NewReader(""), &output); err != nil || !strings.Contains(output.String(), `"delay_ms":42`) {
		t.Fatalf("poll: %s %v", output.String(), err)
	}
	for _, bad := range []string{input + " {}", `{"group":"group","unknown":true}`, strings.Repeat("x", 8193)} {
		if err := run([]string{"--config-dir", dir, "delay-test"}, strings.NewReader(bad), &output); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
}
