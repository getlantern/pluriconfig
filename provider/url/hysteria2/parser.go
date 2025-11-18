package hysteria2

import (
	"context"
	"fmt"
	"net/url"

	"github.com/getlantern/pluriconfig"
	"github.com/getlantern/pluriconfig/model"
)

type parser struct{}

func init() {
	if err := pluriconfig.Register(parser{}); err != nil {
		panic(err)
	}
}

func (p parser) Name() string {
	return string(model.ProviderHysteria2)
}

// Parse parses the given data into a Config object.
func (p parser) Parse(ctx context.Context, data []byte) (*model.AnyConfig, error) {
	providedURL, err := url.Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("couldn't parse hysteria2 URL: %w", err)
	}

	if providedURL.Scheme != "hysteria2" && providedURL.Scheme != "hy2" {
		return nil, fmt.Errorf("invalid hysteria2 URL config")
	}

	hysteria := model.Hysteria{
		ProtocolVersion: 2,
		ServerOptions: model.ServerOptions{
			Server: providedURL.Hostname(),
		},
		ServerPorts: providedURL.Port(),
		Name:        providedURL.Fragment,
	}

	if pass, exist := providedURL.User.Password(); exist && pass != "" {
		hysteria.AuthPayload = providedURL.User.Username() + ":" + pass
	} else {
		hysteria.AuthPayload = providedURL.User.Username()
	}

	queryParams := providedURL.Query()
	hysteria.ServerPorts = queryParams.Get("mport")
	hysteria.SNI = queryParams.Get("sni")
	hysteria.AllowInsecure = queryParams.Get("insecure") == "1" || queryParams.Get("insecure") == "true"
	hysteria.Obfuscation = queryParams.Get("obfs-password")

	return &model.AnyConfig{
		Type:    model.ProviderHysteria2,
		Options: hysteria,
	}, nil
}

func (p parser) Serialize(ctx context.Context, config *model.AnyConfig) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
