// Package singbox implements a parser for SingBox configuration files.
package singbox

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/getlantern/pluriconfig"
	"github.com/getlantern/pluriconfig/model"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badoption"
)

type parser struct{}

func init() {
	if err := pluriconfig.Register(parser{}); err != nil {
		panic(err)
	}
}

func (p parser) Name() string {
	return string(model.ProviderSingBox)
}

type Options struct {
	Outbounds []option.Outbound `json:"outbounds,omitempty"`
	Endpoints []option.Endpoint `json:"endpoints,omitempty"`
}

// Parse parses the given data into a Config object.
func (p parser) Parse(ctx context.Context, data []byte) (*model.AnyConfig, error) {
	var config Options
	if err := json.UnmarshalContext(ctx, data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sing-box config: %w", err)
	}

	return &model.AnyConfig{
		Type:    model.ProviderSingBox,
		Options: config,
	}, nil
}

// Serialize serializes the given Config object into a sing-box json format.
func (p parser) Serialize(ctx context.Context, config *model.AnyConfig) ([]byte, error) {
	var opts Options
	var ok bool
	switch config.Type {
	case model.ProviderSingBox:
		if opts, ok = config.Options.(Options); !ok {
			return nil, fmt.Errorf("invalid options type: %T", config.Options)
		}
	case model.ProviderURL:
		opts = Options{}
		url, ok := config.Options.(url.URL)
		if !ok {
			return nil, fmt.Errorf("invalid options type: %T", config.Options)
		}
		outbound, err := outboundFromURL(url)
		if err != nil {
			return nil, fmt.Errorf("failed to generate outbound from URL: %w", err)
		}

		opts.Outbounds = []option.Outbound{*outbound}
	default:
		return nil, fmt.Errorf("unsupported provider: %s", config.Type)
	}

	data, err := json.MarshalContext(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sing-box config: %w", err)
	}
	return data, nil
}

func outboundFromURL(providedURL url.URL) (*option.Outbound, error) {
	port, err := strconv.ParseUint(providedURL.Port(), 10, 16)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse server port: %w", err)
	}

	switch providedURL.Scheme {
	case "ss", "shadowsocks":
		ssOptions := option.ShadowsocksOutboundOptions{
			ServerOptions: option.ServerOptions{
				Server:     providedURL.Hostname(),
				ServerPort: uint16(port),
			},
		}
		decodedUsername, err := base64.StdEncoding.DecodeString(providedURL.User.Username())
		if err != nil {
			// If the username is not base64 encoded, use it directly
			ssOptions.Method = "none"
			ssOptions.Password = providedURL.User.Username()
		} else {
			splitUsername := strings.Split(string(decodedUsername), ":")
			if len(splitUsername) != 2 {
				return nil, fmt.Errorf("couldn't parse shadowsocks method and password from username")
			}
			ssOptions.Method = splitUsername[0]
			ssOptions.Password = splitUsername[1]
		}

		return &option.Outbound{
			Type:    constant.TypeShadowsocks,
			Tag:     providedURL.Fragment,
			Options: ssOptions,
		}, nil
	case "trojan":
		queryParams := providedURL.Query()
		v2rTransportOpts := model.V2RTransportOpts{
			Type:        queryParams.Get("type"),
			Host:        queryParams.Get("host"),
			Path:        queryParams.Get("path"),
			Method:      queryParams.Get("method"),
			ServiceName: queryParams.Get("serviceName"),
		}

		trojanOptions := option.TrojanOutboundOptions{
			Password: providedURL.User.Username(),
			ServerOptions: option.ServerOptions{
				Server:     providedURL.Hostname(),
				ServerPort: uint16(port),
			},
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled: true,
				},
			},
			Transport: parseV2RayTransport(v2rTransportOpts),
		}
		if queryParams.Has("sni") {
			trojanOptions.OutboundTLSOptionsContainer.TLS.ServerName = queryParams.Get("sni")
		}
		if queryParams.Has("alpn") {
			trojanOptions.OutboundTLSOptionsContainer.TLS.ALPN = make(badoption.Listable[string], 0)
			trojanOptions.OutboundTLSOptionsContainer.TLS.ALPN = append(trojanOptions.OutboundTLSOptionsContainer.TLS.ALPN, queryParams.Get("alpn"))
		}
		if queryParams.Has("allowInsecure") && queryParams.Get("allowInsecure") == "1" {
			trojanOptions.OutboundTLSOptionsContainer.TLS.Insecure = true
		}

		return &option.Outbound{
			Type:    constant.TypeTrojan,
			Tag:     providedURL.Fragment,
			Options: trojanOptions,
		}, nil
	case "vless":
		queryParams := providedURL.Query()
		v2rTransportOpts := model.V2RTransportOpts{
			Type:        queryParams.Get("type"),
			Host:        queryParams.Get("host"),
			Path:        queryParams.Get("path"),
			Method:      queryParams.Get("method"),
			ServiceName: queryParams.Get("serviceName"),
		}

		return &option.Outbound{
			Type: constant.TypeVLESS,
			Tag:  providedURL.Fragment,
			Options: option.VLESSOutboundOptions{
				UUID: providedURL.User.Username(),
				ServerOptions: option.ServerOptions{
					Server:     providedURL.Hostname(),
					ServerPort: uint16(port),
				},
				Transport: parseV2RayTransport(v2rTransportOpts),
			},
		}, nil
	case "vmess":
		jsonEncoded, err := base64.StdEncoding.DecodeString(providedURL.Opaque)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse decode vmess base64: %w", err)
		}

		var vmessConfig model.VMESSConfig
		if err := json.Unmarshal(jsonEncoded, &vmessConfig); err != nil {
			return nil, fmt.Errorf("couldn't parse vmess json: %w", err)
		}

		v2rOpts := model.V2RTransportOpts{
			Type:        vmessConfig.Net,
			Host:        vmessConfig.Host,
			Path:        vmessConfig.Path,
			ServiceName: vmessConfig.Host,
		}

		vmessOptions := option.VMessOutboundOptions{
			UUID:     vmessConfig.ID,
			Security: vmessConfig.Security,
			AlterId:  vmessConfig.Aid,
			ServerOptions: option.ServerOptions{
				Server:     vmessConfig.Addr,
				ServerPort: vmessConfig.Port,
			},
			Transport: parseV2RayTransport(v2rOpts),
		}
		if vmessConfig.TLS == "tls" {
			vmessOptions.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: vmessConfig.Sni,
					ALPN:       badoption.Listable[string]{vmessConfig.ALPN},
				},
			}
		}
		return &option.Outbound{
			Type:    constant.TypeVMess,
			Tag:     providedURL.Fragment,
			Options: vmessOptions,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported URL scheme: %s", providedURL.Scheme)
	}
}

func parseV2RayTransport(opts model.V2RTransportOpts) *option.V2RayTransportOptions {
	switch opts.Type {
	case "http":
		return &option.V2RayTransportOptions{
			Type: constant.V2RayTransportTypeHTTP,
			HTTPOptions: option.V2RayHTTPOptions{
				Host: badoption.Listable[string]{opts.Host},
				Path: opts.Path,
			},
		}
	case "httpupgrade", "xhttp":
		return &option.V2RayTransportOptions{
			Type: constant.V2RayTransportTypeHTTPUpgrade,
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
				Host: opts.Host,
				Path: opts.Path,
			},
		}
	case "ws", "wss":
		return &option.V2RayTransportOptions{
			Type: constant.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path: opts.Path,
			},
		}
	case "grpc":
		return &option.V2RayTransportOptions{
			Type: constant.V2RayTransportTypeGRPC,
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: opts.ServiceName,
			},
		}
	case "quic":
		return &option.V2RayTransportOptions{
			Type:        constant.V2RayTransportTypeQUIC,
			QUICOptions: option.V2RayQUICOptions{},
		}
	default:
		return nil
	}
}
