package app

import (
	"context"
	"testing"

	"github.com/neko233-com/netflow/internal/validation"
)

func TestValidationWaitCanBeCanceled(t *testing.T) {
	validationSlots <- struct{}{}
	defer func() { <-validationSlots }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := validateConfigurations(ctx, t.TempDir(), []validation.Config{{Body: []byte("{}")}}); err == nil {
		t.Fatal("canceled request waited for validation slot")
	}
}
