// Package url implements a parser for proxy URL configuration strings.
package url

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/getlantern/pluriconfig"
	"github.com/getlantern/pluriconfig/model"
	"github.com/sagernet/sing-box/option"
)

type parser struct{}

func init() {
	if err := pluriconfig.Register(parser{}); err != nil {
		panic(err)
	}
}

func (p parser) Name() string {
	return string(model.ProviderURL)
}

// Parse parses the given data into a Config object.
func (p parser) Parse(ctx context.Context, data []byte) (*model.AnyConfig, error) {
	urls := make([]*url.URL, 0)
	stringURLs := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ','
	})
	for _, su := range stringURLs {
		if su == "" {
			continue
		}
		parsedURL, err := url.Parse(su)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse provided URL: %w", err)
		}
		urls = append(urls, parsedURL)
	}

	return &model.AnyConfig{
		Type:    model.ProviderURL,
		Options: urls,
	}, nil
}

// Serialize serializes the given Config object into a list of proxy URLs.
func (p parser) Serialize(ctx context.Context, config *model.AnyConfig) ([]byte, error) {
	switch config.Type {
	case model.ProviderURL:
		urls, ok := config.Options.([]url.URL)
		if !ok {
			return nil, fmt.Errorf("invalid options type: %T", config.Options)
		}
		var sb strings.Builder
		for i, u := range urls {
			sb.WriteString(u.String())
			if i < len(urls)-1 {
				sb.WriteString("\n")
			}
		}
		return []byte(sb.String()), nil
	case model.ProviderSingBox:
		opts, ok := config.Options.(model.SingBoxOptions)
		if !ok {
			return nil, fmt.Errorf("invalid options type: %T", config.Options)
		}

		var sb strings.Builder
		for i, outbound := range opts.Outbounds {
			url, err := singBoxOutboundToURL(outbound)
			if err != nil {
				return nil, fmt.Errorf("failed to convert sing-box config to URL: %w", err)
			}
			sb.WriteString(url.String())
			if i < len(opts.Outbounds)-1 {
				sb.WriteString("\n")
			}
		}

		return []byte(sb.String()), nil
	default:
		return nil, fmt.Errorf("unsupported config type: %s", config.Type)
	}
}

func singBoxOutboundToURL(outbound option.Outbound) (*url.URL, error) {
	switch outbound.Type {
	case "shadowsocks":
		ssOptions, ok := outbound.Options.(option.ShadowsocksOutboundOptions)
		if !ok {
			return nil, fmt.Errorf("invalid shadowsocks options type: %T", outbound.Options)
		}
		u := &url.URL{
			Scheme: "ss",
			Host:   fmt.Sprintf("%s:%d", ssOptions.Server, ssOptions.ServerPort),
		}
		if ssOptions.Password != "" && ssOptions.Method != "none" {
			u.User = url.User(base64.StdEncoding.EncodeToString([]byte(ssOptions.Method + ":" + ssOptions.Password)))
		} else if ssOptions.Password != "" {
			u.User = url.User(ssOptions.Password)
		}
		if outbound.Tag != "" {
			u.Fragment = outbound.Tag
		}
		return u, nil
	case "trojan":
		trojanOptions, ok := outbound.Options.(option.TrojanOutboundOptions)
		if !ok {
			return nil, fmt.Errorf("invalid trojan options type: %T", outbound.Options)
		}
		u := &url.URL{
			Scheme: "trojan",
			Host:   fmt.Sprintf("%s:%d", trojanOptions.Server, trojanOptions.ServerPort),
			User:   url.User(trojanOptions.Password),
		}
		if outbound.Tag != "" {
			u.Fragment = outbound.Tag
		}
		queryParams := u.Query()
		queryParams.Add("sni", trojanOptions.TLS.ServerName)
		queryParams.Add("alpn", trojanOptions.TLS.ALPN[0])
		queryParams.Add("allowInsecure", fmt.Sprintf("%t", trojanOptions.TLS.Insecure))
		v2rayConfToQueryParams(queryParams, buildV2RayConfigOpts(trojanOptions.Transport))
		u.RawQuery = queryParams.Encode()
		return u, nil
	case "vless":
		vlessOptions, ok := outbound.Options.(option.VLESSOutboundOptions)
		if !ok {
			return nil, fmt.Errorf("invalid vless options type: %T", outbound.Options)
		}

		u := &url.URL{
			Scheme: "vless",
			Host:   fmt.Sprintf("%s:%d", vlessOptions.Server, vlessOptions.ServerPort),
			User:   url.User(vlessOptions.UUID),
		}

		if outbound.Tag != "" {
			u.Fragment = outbound.Tag
		}

		queryParams := u.Query()
		v2rayConfToQueryParams(queryParams, buildV2RayConfigOpts(vlessOptions.Transport))
		u.RawQuery = queryParams.Encode()

		return u, nil
	case "vmess":
		vmessOptions, ok := outbound.Options.(option.VMessOutboundOptions)
		if !ok {
			return nil, fmt.Errorf("invalid vmess options type: %T", outbound.Options)
		}

		cfg := model.VMESSConfig{
			Addr:     vmessOptions.Server,
			Port:     vmessOptions.ServerPort,
			ID:       vmessOptions.UUID,
			Security: vmessOptions.Security,
			Aid:      vmessOptions.AlterId,
			ALPN:     vmessOptions.TLS.ALPN[0],
			Sni:      vmessOptions.TLS.ServerName,
		}

		if vmessOptions.TLS.Enabled {
			cfg.TLS = "tls"
		}

		switch vmessOptions.Transport.Type {
		case "ws", "wss":
			cfg.Net = "ws"
			cfg.Path = vmessOptions.Transport.WebsocketOptions.Path
		case "grpc":
			cfg.Net = "grpc"
			cfg.Host = vmessOptions.Transport.GRPCOptions.ServiceName
		case "http":
			cfg.Net = "http"
			cfg.Host = vmessOptions.Transport.HTTPOptions.Host[0]
			cfg.Path = vmessOptions.Transport.HTTPOptions.Path
		case "httpupgrade":
			cfg.Net = "httpupgrade"
			cfg.Host = vmessOptions.Transport.HTTPUpgradeOptions.Host
		}

		encodedJSONConfig, err := json.Marshal(cfg)
		if err != nil {
			return nil, fmt.Errorf("couldn't marshal vmess config to json: %w", err)
		}

		u := &url.URL{
			Scheme: "vmess",
			Host:   "",
			Path:   base64.StdEncoding.EncodeToString(encodedJSONConfig),
		}
		return u, nil
	default:
		return nil, fmt.Errorf("unsupported outbound type: %s", outbound.Type)
	}
}

func buildV2RayConfigOpts(opts *option.V2RayTransportOptions) model.V2RTransportOpts {
	v2rayOpts := model.V2RTransportOpts{
		Type: opts.Type,
	}
	switch opts.Type {
	case "ws", "wss":
		v2rayOpts.Path = opts.WebsocketOptions.Path
	case "grpc":
		v2rayOpts.ServiceName = opts.GRPCOptions.ServiceName
	case "httpupgrade":
		v2rayOpts.Path = opts.HTTPUpgradeOptions.Path
		v2rayOpts.Host = opts.HTTPUpgradeOptions.Host
	case "http":
		v2rayOpts.Path = opts.HTTPOptions.Path
		v2rayOpts.Host = opts.HTTPOptions.Host[0]
	}

	return v2rayOpts
}

func v2rayConfToQueryParams(queryParams url.Values, v2rayOpts model.V2RTransportOpts) {
	queryParams.Add("type", v2rayOpts.Type)
	if v2rayOpts.Host != "" {
		queryParams.Add("host", v2rayOpts.Host)
	}
	if v2rayOpts.Path != "" {
		queryParams.Add("path", v2rayOpts.Path)
	}
	if v2rayOpts.ServiceName != "" {
		queryParams.Add("serviceName", v2rayOpts.ServiceName)
	}
}
