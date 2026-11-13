package app

import (
	"errors"
	"fmt"

	"github.com/metacubex/mihomo/hub/executor"
	"github.com/neko233-com/netflow/internal/profile"
	"go.yaml.in/yaml/v3"
)

// Validate the document shape before persisting a subscription. Mihomo also
// validates its full schema when the profile is activated.
func validateProfile(body []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("配置 YAML 无效: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode || len(doc.Content[0].Content) == 0 {
		return errors.New("配置必须是非空的 YAML 映射")
	}
	if _, err := executor.ParseWithBytes(profile.EnsureMixedPort(body, 7897)); err != nil {
		return fmt.Errorf("内核配置无效: %w", err)
	}
	return nil
}
