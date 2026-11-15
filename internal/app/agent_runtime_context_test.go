package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/neko233-com/netflow/internal/agent"
)

func TestCanceledAgentRequestLeavesConfigBarrier(t *testing.T) {
	d := newSerialDispatcher()
	defer d.close()
	entered := make(chan struct{}, 1)
	a := &App{}
	a.dispatch = func(fn func()) { d.call(func() { fn(); entered <- struct{}{} }) }
	barrier := &guiConfigOperation{done: make(chan struct{})}
	a.guiBarrier.Store(barrier)
	defer close(barrier.done)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := a.dispatchAgent(ctx, "groups", nil); result <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not reach barrier")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("request cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled request remained queued behind the configuration barrier")
	}
}

func TestCanceledQueuedAgentRequestsReleaseBridgeCapacity(t *testing.T) {
	d := newSerialDispatcher()
	defer d.close()
	entered := make(chan struct{}, 64)
	a := &App{dir: t.TempDir(), headlessRecovery: true}
	a.dispatch = func(fn func()) { d.call(func() { fn(); entered <- struct{}{} }) }
	barrier := &guiConfigOperation{done: make(chan struct{})}
	a.guiBarrier.Store(barrier)
	defer close(barrier.done)
	if err := a.startAgent(); err != nil {
		t.Fatal(err)
	}
	defer a.stopAgent()
	client := agent.Client{Dir: a.dir, Timeout: 5 * time.Second}
	// More than the bridge's 32 ordinary request slots must be able to enter
	// sequentially while the original transaction remains blocked.
	for i := 0; i < 40; i++ {
		deadline := time.Now().Add(3 * time.Second)
		for {
			ctx, cancel := context.WithCancel(context.Background())
			result := make(chan error, 1)
			go func() { result <- client.Call(ctx, "groups", nil, nil) }()
			select {
			case <-entered:
				cancel()
				if err := <-result; !errors.Is(err, context.Canceled) {
					t.Fatalf("request %d cancellation: %v", i, err)
				}
			case err := <-result:
				cancel()
				if err != nil && strings.Contains(err.Error(), "busy") && time.Now().Before(deadline) {
					time.Sleep(25 * time.Millisecond)
					continue
				}
				t.Fatalf("request %d did not reach the barrier: %v", i, err)
			case <-time.After(3 * time.Second):
				cancel()
				t.Fatalf("request %d did not reach the barrier", i)
			}
			break
		}
	}
}

func TestAgentCancellationTargetsOnlyItsOwnTransaction(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "stale"}[stale], func(t *testing.T) {
			d := newSerialDispatcher()
			defer d.close()
			dispatched := make(chan struct{})
			a := &App{}
			a.dispatch = func(fn func()) { d.call(func() { fn(); close(dispatched) }) }
			cancelled := false
			current := &guiConfigOperation{cancel: func() { cancelled = true }}
			old := &guiConfigOperation{cancel: func() { t.Error("stale transaction canceled") }}
			d.call(func() { a.guiOperation = current })
			if stale {
				a.cancelAgentConfigOperation(old)
			} else {
				a.cancelAgentConfigOperation(current)
			}
			select {
			case <-dispatched:
			case <-time.After(time.Second):
				t.Fatal("cancellation was not dispatched")
			}
			if cancelled != !stale {
				t.Fatalf("current transaction cancellation: %t", cancelled)
			}
		})
	}
}
