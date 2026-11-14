package ui

import (
	"errors"
	"testing"
)

func TestChainControlsCallBackendAndPreserveStateOnFailure(t *testing.T) {
	m := DemoModel()
	m.Router.Replace("/proxies")
	var gotTarget string
	var gotNodes []ProxyNode
	disconnects := 0
	m.Hooks.ChainAvailable = func() bool { return true }
	m.Hooks.ConnectChainAsync = func(target string, nodes []ProxyNode, done func(error)) {
		gotTarget = target
		gotNodes = nodes
		done(nil)
	}
	m.Hooks.DisconnectChain = func() error {
		disconnects++
		if disconnects == 1 {
			return errors.New("disconnect failed")
		}
		return nil
	}
	tt := renderModel(m, WindowWidth, WindowHeight, false)
	if err := tt.Click("chain-toggle"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("chain-enable"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("node-Proxy-香港 01"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("node-Proxy-香港 02"); err != nil {
		t.Fatal(err)
	}
	if err := tt.Click("chain-connect"); err != nil {
		t.Fatal(err)
	}
	if !m.Chain.Connected || gotTarget != "Proxy" || len(gotNodes) != 2 || gotNodes[0].SourceGroup != "Proxy" {
		t.Fatalf("connect: %+v %q %+v", m.Chain, gotTarget, gotNodes)
	}
	if err := tt.Click("chain-connect"); err != nil {
		t.Fatal(err)
	}
	if !m.Chain.Connected || m.Notice != "disconnect failed" {
		t.Fatal("failed disconnect changed UI state")
	}
	if err := tt.Click("chain-connect"); err != nil {
		t.Fatal(err)
	}
	if m.Chain.Connected || disconnects != 2 {
		t.Fatal("disconnect did not reach backend")
	}
}
