package app

import (
	"testing"
	"time"
)

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
