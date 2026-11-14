package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
	"github.com/neko233-com/netflow/internal/ui"
)

func TestAgentDelayJobsValidateBoundAndRedact(t *testing.T) {
	now := time.Now()
	a := &App{core: &switchTestEngine{running: true, id: "profile"}, model: ui.NewModel(ui.HomeState{})}
	input := agent.DelayArgs{Group: "test", Node: "DIRECT", URL: "https://example.test/?token=synthetic-secret", TimeoutMS: 2500}
	var complete func(int, error)
	start := func(group, node, url string, timeout time.Duration, profile string, done func(int, error)) {
		if group != "test" || node != "DIRECT" || url != input.URL || timeout != 2500*time.Millisecond || profile != "profile" {
			t.Fatal("wrong probe parameters")
		}
		complete = done
	}
	job, err := a.beginDelayJob(input, now, start)
	if err != nil || job.State != "pending" {
		t.Fatalf("job: %+v %v", job, err)
	}
	encoded, _ := json.Marshal(job)
	if strings.Contains(string(encoded), "synthetic-secret") {
		t.Fatal("job exposed URL")
	}
	complete(42, nil)
	job, err = a.getDelayJob(job.JobID, time.Now())
	if err != nil || job.State != "succeeded" || job.DelayMS != 42 {
		t.Fatalf("result: %+v %v", job, err)
	}
	if _, err := a.getDelayJob(job.JobID, time.Now().Add(delayJobRetention+time.Second)); err == nil {
		t.Fatal("expired job retained")
	}
	for _, bad := range []agent.DelayArgs{
		{Group: "test", Node: "missing"}, {Group: "test", Node: "DIRECT", URL: "file:///private"},
		{Group: "test", Node: "DIRECT", URL: "https://user:pass@example.test"}, {Group: "test", Node: "DIRECT", TimeoutMS: 99},
		{Group: "test", Node: "DIRECT", TimeoutMS: 60001}, {Node: "DIRECT"},
	} {
		if _, err := a.beginDelayJob(bad, now, start); err == nil {
			t.Fatalf("accepted invalid request: %+v", bad)
		}
	}
	for _, tc := range []struct {
		err   error
		state string
	}{{context.Canceled, "canceled"}, {context.DeadlineExceeded, "timed_out"}, {errors.New("https://example.test/?token=synthetic-secret"), "failed"}} {
		j, err := a.beginDelayJob(input, now, start)
		if err != nil {
			t.Fatal(err)
		}
		complete(0, tc.err)
		j, err = a.getDelayJob(j.JobID, time.Now())
		if err != nil || j.State != tc.state || strings.Contains(j.Error, "synthetic-secret") {
			t.Fatalf("unsafe result: %+v %v", j, err)
		}
	}
	for i := 0; i < maxPendingDelayJobs; i++ {
		if _, err := a.beginDelayJob(input, now, start); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.beginDelayJob(input, now, start); err == nil {
		t.Fatal("pending capacity was not enforced")
	}
}
