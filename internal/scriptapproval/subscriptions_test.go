package scriptapproval

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestSubscriptionStorageAndPrunePreserveReferences(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	first, err := StoreSubscription(ctx, root, []byte("private first"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := StoreSubscription(ctx, root, []byte("private second"))
	if err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(root, subscriptionDir, "user.yaml")
	if err := os.WriteFile(unknown, []byte("user"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PruneSubscriptions(ctx, root, []string{first}, func() error { return errors.New("changed") }); err == nil {
		t.Fatal("changed catalog accepted")
	}
	if _, err := os.Stat(filepath.Join(root, second)); err != nil {
		t.Fatal("guard failure removed file")
	}
	result, err := PruneSubscriptions(ctx, root, []string{first}, func() error { return nil })
	if err != nil || result.Removed != 1 || result.Bytes != int64(len("private second")) {
		t.Fatalf("unexpected prune: %+v %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(root, first)); err != nil {
		t.Fatal("referenced file removed")
	}
	if _, err := os.Stat(filepath.Join(root, second)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unreferenced file remains")
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatal("user file removed")
	}
}

func TestSubscriptionStorageBoundsAndCancellation(t *testing.T) {
	root := t.TempDir()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := StoreSubscription(canceled, root, []byte("data")); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored", err)
	}
	if err := os.MkdirAll(filepath.Join(root, subscriptionDir), 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxSubscriptionFiles; i++ {
		name := fmt.Sprintf("netflow-%032x.yaml", i)
		if err := os.WriteFile(filepath.Join(root, subscriptionDir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := StoreSubscription(context.Background(), root, []byte("more")); !errors.Is(err, ErrSubscriptionCacheFull) {
		t.Fatal("file count limit ignored", err)
	}
}

func TestSubscriptionPrunePreservesReferencedFileAliases(t *testing.T) {
	root := t.TempDir()
	retained, err := StoreSubscription(context.Background(), root, []byte("retained"))
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join("profiles", "alias.yaml")
	if err := os.Link(filepath.Join(root, retained), filepath.Join(root, alias)); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	result, err := PruneSubscriptions(context.Background(), root, []string{alias}, func() error { return nil })
	if err != nil || result.Removed != 0 {
		t.Fatalf("referenced file alias was pruned: %+v %v", result, err)
	}
	if _, err := os.Stat(filepath.Join(root, retained)); err != nil {
		t.Fatal("managed alias disappeared", err)
	}
}
