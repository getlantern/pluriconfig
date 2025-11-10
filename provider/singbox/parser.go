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
	_ "github.com/getlantern/pluriconfig/provider/url/hysteria"
	_ "github.com/getlantern/pluriconfig/provider/url/hysteria2"
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

// Parse parses the given data into a Config object.
func (p parser) Parse(ctx context.Context, data []byte) (*model.AnyConfig, error) {
	var config model.SingBoxOptions
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
	var opts model.SingBoxOptions
	var ok bool
	switch config.Type {
	case model.ProviderSingBox:
		if opts, ok = config.Options.(model.SingBoxOptions); !ok {
			return nil, fmt.Errorf("invalid options type: %T", config.Options)
		}
	case model.ProviderURL:
		opts = model.SingBoxOptions{Outbounds: make([]option.Outbound, 0)}
		urls, ok := config.Options.([]url.URL)
		if !ok {
			return nil, fmt.Errorf("invalid options type: %T", config.Options)
		}
		for _, url := range urls {
			outbound, err := outboundFromURL(ctx, url)
			if err != nil {
				return nil, fmt.Errorf("failed to generate outbound from URL: %w", err)
			}

			opts.Outbounds = append(opts.Outbounds, *outbound)
		}
	case model.ProviderClash:
		opts = model.SingBoxOptions{Outbounds: make([]option.Outbound, 0)}
		clashConfig, ok := config.Options.([]model.Outbound)
		if !ok {
			return nil, fmt.Errorf("invalid options type: %T", config.Options)
		}
		for _, clashOutbound := range clashConfig {
			outbound, err := outboundFromClash(clashOutbound)
			if err != nil {
				return nil, fmt.Errorf("failed to generate outbound from Clash config: %w", err)
			}

			opts.Outbounds = append(opts.Outbounds, *outbound)
		}
	default:
		return nil, fmt.Errorf("unsupported provider: %s", config.Type)
	}

	data, err := json.MarshalContext(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sing-box config: %w", err)
	}
	return data, nil
}

func outboundFromURL(ctx context.Context, providedURL url.URL) (*option.Outbound, error) {
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
	case "hysteria":
		hysteriaProvider, exist := pluriconfig.GetProvider(string(model.ProviderHysteria))
		if !exist {
			return nil, fmt.Errorf("hysteria config provider not found")
		}

		hysteriaConfig, err := hysteriaProvider.Parse(ctx, []byte(providedURL.String()))
		if err != nil {
			return nil, fmt.Errorf("failed to parse hysteria URL: %w", err)
		}
		config, ok := hysteriaConfig.Options.(model.Hysteria)
		if !ok {
			return nil, fmt.Errorf("invalid hysteria config options type: %T", hysteriaConfig.Options)
		}

		return buildHysteriaSingBox(config)
	case "hysteria2", "hy2":
		hysteria2Provider, exist := pluriconfig.GetProvider(string(model.ProviderHysteria2))
		if !exist {
			return nil, fmt.Errorf("hysteria2 config provider not found")
		}
		hysteria2Config, err := hysteria2Provider.Parse(ctx, []byte(providedURL.String()))
		if err != nil {
			return nil, fmt.Errorf("failed to parse hysteria2 URL: %w", err)
		}
		config, ok := hysteria2Config.Options.(model.Hysteria)
		if !ok {
			return nil, fmt.Errorf("invalid hysteria2 config options type: %T", hysteria2Config.Options)
		}
		return buildHysteria2SingBox(config)
	default:
		return nil, fmt.Errorf("unsupported URL scheme: %s", providedURL.Scheme)
	}
}

func buildHysteriaSingBox(config model.Hysteria) (*option.Outbound, error) {
	options := option.HysteriaOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server: config.Server,
		},
		UpMbps:              config.UploadMbps,
		DownMbps:            config.DownloadMbps,
		Obfs:                config.Obfuscation,
		DisableMTUDiscovery: config.DisableMTUDiscovery,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:  true,
				Insecure: config.AllowInsecure,
			},
		},
	}
	if config.Port != "" {
		port, err := strconv.ParseUint(config.Port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse server port: %w", err)
		}
		options.ServerPort = uint16(port)
	}

	switch config.AuthPayloadType {
	case 1:
		// case string
		options.AuthString = config.AuthPayload
	case 2:
		// case base64
		options.Auth = []byte(config.AuthPayload)
	}

	if config.StreamReceiveWindow > 0 {
		options.ReceiveWindow = uint64(config.StreamReceiveWindow)
	}

	if config.ConnReceiveWindow > 0 {
		options.ReceiveWindowConn = uint64(config.ConnReceiveWindow)
	}

	if config.SNI != "" {
		options.OutboundTLSOptionsContainer.TLS.ServerName = config.SNI
	}

	if config.ALPN != "" {
		options.OutboundTLSOptionsContainer.TLS.ALPN = strings.FieldsFunc(config.ALPN, func(r rune) bool { return r == ',' || r == '\n' })
	}

	if config.CaText != "" {
		options.OutboundTLSOptionsContainer.TLS.Certificate = badoption.Listable[string]{config.CaText}
	}

	return &option.Outbound{
		Type:    constant.TypeHysteria,
		Tag:     config.Name,
		Options: options,
	}, nil
}

func buildHysteria2SingBox(config model.Hysteria) (*option.Outbound, error) {
	options := option.Hysteria2OutboundOptions{
		ServerOptions: option.ServerOptions{
			Server: config.Server,
		},
		UpMbps:      config.UploadMbps,
		DownMbps:    config.DownloadMbps,
		HopInterval: badoption.Duration(config.HopInterval),
		Password:    config.AuthPayload,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:  true,
				Insecure: config.AllowInsecure,
				ALPN:     badoption.Listable[string]{"h3"},
			},
		},
	}
	if config.Port != "" {
		port, err := strconv.ParseUint(config.Port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse server port: %w", err)
		}
		options.ServerPort = uint16(port)
	} else {
		options.ServerPorts = hopPortsToSingboxList(config.ServerPorts)
	}

	if config.Obfuscation != "" {
		options.Obfs = &option.Hysteria2Obfs{
			Type:     "salamander",
			Password: config.Obfuscation,
		}
	}

	if config.SNI != "" {
		options.OutboundTLSOptionsContainer.TLS.ServerName = config.SNI
	}

	if config.CaText != "" {
		options.OutboundTLSOptionsContainer.TLS.Certificate = badoption.Listable[string]{config.CaText}
	}

	return &option.Outbound{
		Type:    constant.TypeHysteria2,
		Tag:     config.Name,
		Options: options,
	}, nil

}

func hopPortsToSingboxList(serverPorts string) []string {
	var portList []string
	for _, r := range strings.Split(serverPorts, ",") {
		pRange := strings.ReplaceAll(r, "-", ":")
		if len(strings.Split(pRange, ":")) == 2 {
			portList = append(portList, pRange)
		}
	}
	return portList
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
		headers := make(badoption.HTTPHeader)
		for key, values := range opts.Headers {
			headers[key] = badoption.Listable[string](values)
		}
		return &option.V2RayTransportOptions{
			Type: constant.V2RayTransportTypeWebsocket,
			WebsocketOptions: option.V2RayWebsocketOptions{
				Path:    opts.Path,
				Headers: headers,
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

func outboundFromClash(outbound model.Outbound) (*option.Outbound, error) {
	switch outbound.Type {
	case "shadowsocks":
		ssOpts, ok := outbound.Options.(model.ShadowsocksOutboundOptions)
		if !ok {
			return nil, fmt.Errorf("invalid shadowsocks outbound options type: %T", outbound.Options)
		}
		port, err := strconv.ParseUint(ssOpts.Port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse server port: %w", err)
		}
		return &option.Outbound{
			Type: constant.TypeShadowsocks,
			Tag:  outbound.Name,
			Options: option.ShadowsocksOutboundOptions{
				ServerOptions: option.ServerOptions{
					Server:     ssOpts.Server,
					ServerPort: uint16(port),
				},
				Method:   ssOpts.Cipher,
				Password: ssOpts.Password,
			},
		}, nil
	case "trojan":
		trojanOpts, ok := outbound.Options.(model.TrojanOutboundOptions)
		if !ok {
			return nil, fmt.Errorf("invalid trojan outbound options type: %T", outbound.Options)
		}
		port, err := strconv.ParseUint(trojanOpts.Port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse server port: %w", err)
		}
		var transport *option.V2RayTransportOptions
		if trojanOpts.GRPCOpts != nil {
			v2rTransportOpts := model.V2RTransportOpts{
				Type:        "grpc",
				ServiceName: trojanOpts.GRPCOpts.ServiceName,
			}
			transport = parseV2RayTransport(v2rTransportOpts)
		}

		if trojanOpts.WSOpts != nil {
			v2rTransportOpts := model.V2RTransportOpts{
				Type:    "ws",
				Path:    trojanOpts.WSOpts.Path,
				Headers: trojanOpts.WSOpts.Headers,
			}
			transport = parseV2RayTransport(v2rTransportOpts)
		}

		var outboundTLSOptionContainer option.OutboundTLSOptionsContainer
		if trojanOpts.SNI != "" || trojanOpts.SkipCertVerify {
			outboundTLSOptionContainer = option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: trojanOpts.SNI,
					Insecure:   trojanOpts.SkipCertVerify,
					ALPN:       trojanOpts.ALPN,
				},
			}
		}

		return &option.Outbound{
			Type: constant.TypeTrojan,
			Tag:  outbound.Name,
			Options: option.TrojanOutboundOptions{
				Password: trojanOpts.Password,
				ServerOptions: option.ServerOptions{
					Server:     trojanOpts.Server,
					ServerPort: uint16(port),
				},
				Transport:                   transport,
				OutboundTLSOptionsContainer: outboundTLSOptionContainer,
			},
		}, nil
	case "vmess":
		vmessOpts, ok := outbound.Options.(model.VMESSOutboundOptions)
		if !ok {
			return nil, fmt.Errorf("invalid vmess outbound options type: %T", outbound.Options)
		}
		port, err := strconv.ParseUint(vmessOpts.Port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse server port: %w", err)
		}
		var transport *option.V2RayTransportOptions
		if vmessOpts.GRPCOpts != nil {
			v2rTransportOpts := model.V2RTransportOpts{
				Type:        "grpc",
				ServiceName: vmessOpts.GRPCOpts.ServiceName,
			}
			transport = parseV2RayTransport(v2rTransportOpts)
		}
		if vmessOpts.WSOpts != nil {
			v2rTransportOpts := model.V2RTransportOpts{
				Type:    "ws",
				Path:    vmessOpts.WSOpts.Path,
				Headers: vmessOpts.WSOpts.Headers,
			}
			transport = parseV2RayTransport(v2rTransportOpts)
		}
		if vmessOpts.HTTPOpts != nil {
			v2rTransportOpts := model.V2RTransportOpts{
				Type:    "http",
				Method:  vmessOpts.HTTPOpts.Method,
				Path:    vmessOpts.HTTPOpts.Path[0],
				Headers: vmessOpts.HTTPOpts.Headers,
			}
			transport = parseV2RayTransport(v2rTransportOpts)
		}
		var outboundTLSOptionContainer option.OutboundTLSOptionsContainer
		if vmessOpts.ServerName != "" || vmessOpts.SkipCertVerify {
			outboundTLSOptionContainer = option.OutboundTLSOptionsContainer{
				TLS: &option.OutboundTLSOptions{
					Enabled:    true,
					ServerName: vmessOpts.ServerName,
					Insecure:   vmessOpts.SkipCertVerify,
				},
			}
		}
		return &option.Outbound{
			Type: constant.TypeVMess,
			Tag:  outbound.Name,
			Options: option.VMessOutboundOptions{
				UUID:     vmessOpts.UUID,
				AlterId:  vmessOpts.AlterID,
				Security: vmessOpts.Cipher,
				ServerOptions: option.ServerOptions{
					Server:     vmessOpts.Server,
					ServerPort: uint16(port),
				},
				Transport:                   transport,
				OutboundTLSOptionsContainer: outboundTLSOptionContainer,
			},
		}, nil
	case "hysteria":
		hysteriaOpts, ok := outbound.Options.(model.HysteriaOutboundOptions)
		if !ok {
			return nil, fmt.Errorf("invalid hysteria outbound options type: %T", outbound.Options)
		}

		return buildHysteriaSingBox(model.Hysteria{
			Name:                outbound.Name,
			ProtocolVersion:     1,
			ServerOptions:       hysteriaOpts.ServerOptions,
			ServerPorts:         hysteriaOpts.ServerPorts,
			AuthPayload:         hysteriaOpts.AuthPayload,
			AuthPayloadType:     1,
			UploadMbps:          hysteriaOpts.UploadMbps,
			DownloadMbps:        hysteriaOpts.DownloadMbps,
			Obfuscation:         hysteriaOpts.Obfuscation,
			DisableMTUDiscovery: hysteriaOpts.DisableMTUDiscovery,
			StreamReceiveWindow: hysteriaOpts.StreamReceiveWindow,
			ConnReceiveWindow:   hysteriaOpts.ConnReceiveWindow,
			SNI:                 hysteriaOpts.SNI,
			ALPN:                strings.Join(hysteriaOpts.ALPN, ","),
			AllowInsecure:       hysteriaOpts.AllowInsecure,
		})
	case "hysteria2":
		hysteria2Opts, ok := outbound.Options.(model.Hysteria2OutboundOptions)
		if !ok {
			return nil, fmt.Errorf("invalid hysteria2 outbound options type: %T", outbound.Options)
		}
		return buildHysteria2SingBox(model.Hysteria{
			Name:            outbound.Name,
			ProtocolVersion: 2,
			ServerOptions:   hysteria2Opts.ServerOptions,
			ServerPorts:     hysteria2Opts.ServerPorts,
			AuthPayload:     hysteria2Opts.Password,
			AuthPayloadType: 1,
			UploadMbps:      hysteria2Opts.UploadMbps,
			DownloadMbps:    hysteria2Opts.DownloadMbps,
			Obfuscation:     hysteria2Opts.ObfuscationPassword,
			SNI:             hysteria2Opts.SNI,
			AllowInsecure:   hysteria2Opts.AllowInsecure,
		})

	default:
		return nil, fmt.Errorf("unsupported outbound type: %s", outbound.Type)
	}
}
