package pluriconfig

import (
	"context"
	"fmt"
	"sync"

	"github.com/getlantern/pluriconfig/model"
)

var (
	providersMu sync.RWMutex
	providers   = make(map[string]Provider)
)

// Provider is an interface that defines methods for configuration providers.
type Provider interface {
	// Name returns the name of the provider.
	Name() string
	// Parse takes a byte slice and returns a Config object or an error.
	Parse(ctx context.Context, data []byte) (*model.AnyConfig, error)
	// Serialize takes a Config object and returns a byte slice or an error
	Serialize(ctx context.Context, config *model.AnyConfig) ([]byte, error)
}

func Register(p Provider) error {
	providersMu.Lock()
	defer providersMu.Unlock()

	name := p.Name()
	if name == "" {
		return fmt.Errorf("provider name cannot be empty")
	}

	if _, exists := providers[name]; exists {
		return nil
	}

	providers[name] = p
	return nil
}

func GetProvider(name string) (Provider, bool) {
	providersMu.RLock()
	defer providersMu.RUnlock()

	p, exists := providers[name]
	return p, exists
}

func Providers() []string {
	providersMu.RLock()
	defer providersMu.RUnlock()

	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	return names
}
