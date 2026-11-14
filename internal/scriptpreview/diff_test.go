package scriptpreview

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSummarizeDoesNotRevealValuesOrUnknownNames(t *testing.T) {
	before := []byte("rules: ['MATCH,DIRECT']\ndns: {enable: true}\nsecret: synthetic-old\n")
	after := []byte("rules: ['DOMAIN,example.test,DIRECT', 'MATCH,DIRECT']\ndns: {enable: false}\nsecret: synthetic-new\nsynthetic-private-key: synthetic-value\n")
	changes, err := Summarize(context.Background(), before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(changes.Fields, []string{"dns", "rules", "secret"}) || changes.OtherCount != 1 {
		t.Fatalf("unexpected summary: %+v", changes)
	}
	data, _ := json.Marshal(changes)
	if strings.Contains(string(data), "synthetic") || strings.Contains(string(data), "example.test") {
		t.Fatal("summary exposed values or unknown names")
	}
}
func TestSummarizeDetectsOrderAndCancellation(t *testing.T) {
	before := []byte("dns:\n  nameserver-policy:\n    a.example: 1.1.1.1\n    b.example: 8.8.8.8\n")
	after := []byte("dns:\n  nameserver-policy:\n    b.example: 8.8.8.8\n    a.example: 1.1.1.1\n")
	changes, err := Summarize(context.Background(), before, after)
	if err != nil || !reflect.DeepEqual(changes.Fields, []string{"dns"}) {
		t.Fatalf("order change missed: %+v %v", changes, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Summarize(ctx, before, after); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
}
