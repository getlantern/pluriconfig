package hysteria

import (
	"context"
	"fmt"
	"net/url"
	"strconv"

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
	return string(model.ProviderHysteria)
}

// Parse parses the given data into a Config object.
func (p parser) Parse(ctx context.Context, data []byte) (*model.AnyConfig, error) {
	providedURL, err := url.Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("couldn't parse hysteria URL: %w", err)
	}

	if providedURL.Scheme != "hysteria" {
		return nil, fmt.Errorf("invalid hysteria URL config")
	}

	hysteria := model.Hysteria{
		ProtocolVersion: 1,
		ServerOptions: model.ServerOptions{
			Server: providedURL.Hostname(),
			Port:   providedURL.Port(),
		},
		Name: providedURL.Fragment,
	}

	queryParams := providedURL.Query()
	hysteria.ServerPorts = queryParams.Get("mport")
	hysteria.SNI = queryParams.Get("peer")
	if queryParams.Has("auth") && queryParams.Get("auth") != "" {
		hysteria.AuthPayload = queryParams.Get("auth")
		hysteria.AuthPayloadType = 1
	}

	hysteria.AllowInsecure = queryParams.Get("allowInsecure") == "1" ||
		queryParams.Get("allowInsecure") == "true" ||
		queryParams.Get("insecure") == "1" ||
		queryParams.Get("insecure") == "true"

	up := 10
	if queryParams.Has("upmbps") {
		if val := queryParams.Get("upmbps"); val != "" {
			up, err = strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("couldn't parse upmbps: %w", err)
			}
		}
	}
	hysteria.UploadMbps = up

	down := 50
	if queryParams.Has("downmbps") {
		if val := queryParams.Get("downmbps"); val != "" {
			down, err = strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("couldn't parse downmbps: %w", err)
			}
		}
	}
	hysteria.DownloadMbps = down
	hysteria.ALPN = queryParams.Get("alpn")
	hysteria.Obfuscation = queryParams.Get("obfsParam")

	switch queryParams.Get("protocol") {
	case "faketcp":
		hysteria.Protocol = 1
	case "wechat-video":
		hysteria.Protocol = 2
	}

	return &model.AnyConfig{
		Type:    model.ProviderHysteria,
		Options: hysteria,
	}, nil
}

func (p parser) Serialize(ctx context.Context, config *model.AnyConfig) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
