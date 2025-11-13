// Package singbox implements a parser for SingBox configuration files.
package singbox

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"

	"github.com/getlantern/pluriconfig"
	"github.com/getlantern/pluriconfig/model"
	_ "github.com/getlantern/pluriconfig/provider/url/csv"
	_ "github.com/getlantern/pluriconfig/provider/url/ducksoft"
	_ "github.com/getlantern/pluriconfig/provider/url/kitsunebi"
	_ "github.com/getlantern/pluriconfig/provider/url/qrcode"
	_ "github.com/getlantern/pluriconfig/provider/url/std"

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
	switch providedURL.Scheme {
	case "ss", "shadowsocks":
		port, err := strconv.ParseUint(providedURL.Port(), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("couldn't parse server port: %w", err)
		}
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

		queryParams := providedURL.Query()
		if plugin := queryParams.Get("plugin"); plugin != "" {
			if strings.HasPrefix(plugin, "simple-obfs") {
				plugin = strings.Replace(plugin, "simple-obfs", "obfs-local", 1)
			}

			if plugin != "none" {
				ssOptions.Plugin, ssOptions.PluginOptions, _ = strings.Cut(plugin, ";")
			}
		}

		return &option.Outbound{
			Type:    constant.TypeShadowsocks,
			Tag:     providedURL.Fragment,
			Options: ssOptions,
		}, nil
	case "trojan":
		ducksoftProvider, exist := pluriconfig.GetProvider(string(model.ProviderURLVMessDucksoft))
		if !exist {
			return nil, fmt.Errorf("missing ducksoft provider")
		}

		originalValue, err := providedURL.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("couldn't extract original url value: %w", err)
		}

		config, err := ducksoftProvider.Parse(ctx, originalValue)
		if err != nil {
			return nil, fmt.Errorf("couldn't extract vmess parameters from provided URL: %w", err)
		}
		vmessConfigs, ok := config.Options.([]model.VMess)
		if !ok {
			return nil, fmt.Errorf("got unexpected vmess config type: %T", vmessConfigs)
		}
		if len(vmessConfigs) != 1 {
			return nil, fmt.Errorf("unexpected amount of trojan configs: %d", len(vmessConfigs))
		}

		vmessConfig := vmessConfigs[0]
		port, err := strconv.ParseUint(vmessConfig.Port, 10, 16)
		if err != nil {
			return nil, err
		}
		queryParams := providedURL.Query()
		if peerVal := queryParams.Get("peer"); queryParams.Has("peer") && peerVal != "" {
			vmessConfig.SNI = peerVal
		}
		transport, err := buildSingBoxOutboundTransport(vmessConfig)
		if err != nil {
			return nil, err
		}
		return &option.Outbound{
			Type: constant.TypeTrojan,
			Tag:  vmessConfig.Name,
			Options: option.TrojanOutboundOptions{
				Password: providedURL.User.Username(),
				ServerOptions: option.ServerOptions{
					Server:     vmessConfig.Server,
					ServerPort: uint16(port),
				},
				OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
					TLS: buildSingBoxOutboundTLS(vmessConfig),
				},
				Transport: transport,
			},
		}, nil
	case "vless":
		originalValue, err := providedURL.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("couldn't extract original url value: %w", err)
		}
		providers := []string{
			string(model.ProviderURLVMessStd),
			string(model.ProviderURLVMessDucksoft),
		}

		for _, providerName := range providers {
			provider, exist := pluriconfig.GetProvider(providerName)
			if !exist {
				slog.WarnContext(ctx, "missing provider", slog.String("provider_name", providerName))
				continue
			}

			config, err := provider.Parse(ctx, originalValue)
			if err != nil {
				slog.WarnContext(ctx, "failed to parse vmess config", slog.String("provider_name", providerName), slog.Any("error", err))
				continue
			}

			return buildVLESSOutbound(config)
		}

		return nil, fmt.Errorf("tried all VLESS config providers and couldn't parse successfully")
	case "vmess":
		originalValue, err := providedURL.MarshalBinary()
		if err != nil {
			return nil, fmt.Errorf("couldn't extract original url value: %w", err)
		}
		providers := []string{
			string(model.ProviderURLVMessCSV),
			string(model.ProviderURLVMessQRCode),
			string(model.ProviderURLVMessKitsunebi),
			string(model.ProviderURLVMessStd),
			string(model.ProviderURLVMessDucksoft),
		}
		for _, providerName := range providers {
			provider, exist := pluriconfig.GetProvider(providerName)
			if !exist {
				slog.WarnContext(ctx, "missing provider", slog.String("provider_name", providerName))
				continue
			}

			config, err := provider.Parse(ctx, originalValue)
			if err != nil {
				slog.WarnContext(ctx, "failed to parse vmess config", slog.String("provider_name", providerName), slog.Any("error", err))
				continue
			}

			return buildVMessOutbound(config)
		}

		return nil, fmt.Errorf("tried all VMess config providers and couldn't parse successfully")
	default:
		return nil, fmt.Errorf("unsupported URL scheme: %s", providedURL.Scheme)
	}
}

func buildVLESSOutbound(config *model.AnyConfig) (*option.Outbound, error) {
	vmessConfigs, ok := config.Options.([]model.VMess)
	if !ok {
		return nil, fmt.Errorf("got unexpected vless config type: %T", vmessConfigs)
	}
	if len(vmessConfigs) != 1 {
		return nil, fmt.Errorf("unexpected amount of vless configs: %d", len(vmessConfigs))
	}

	vmessConfig := vmessConfigs[0]
	port, err := strconv.ParseUint(vmessConfig.Port, 10, 16)
	if err != nil {
		return nil, err
	}
	transport, err := buildSingBoxOutboundTransport(vmessConfig)
	if err != nil {
		return nil, err
	}

	vlessOptions := option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     vmessConfig.Server,
			ServerPort: uint16(port),
		},
		UUID: vmessConfig.UUID,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: buildSingBoxOutboundTLS(vmessConfig),
		},
		Transport: transport,
	}
	if vmessConfig.Encryption != "" && vmessConfig.Encryption != "auto" {
		vlessOptions.Flow = vmessConfig.Encryption
	}
	switch vmessConfig.PacketEncoding {
	case 0:
		vlessOptions.PacketEncoding = nil
	case 1:
		packetEncoding := "packetaddr"
		vlessOptions.PacketEncoding = &packetEncoding
	case 2:
		packetEncoding := "xudp"
		vlessOptions.PacketEncoding = &packetEncoding
	}

	return &option.Outbound{
		Type:    constant.TypeVLESS,
		Tag:     vmessConfig.Name,
		Options: vlessOptions,
	}, nil
}

func buildVMessOutbound(config *model.AnyConfig) (*option.Outbound, error) {
	vmessConfigs, ok := config.Options.([]model.VMess)
	if !ok {
		return nil, fmt.Errorf("got unexpected vmess config type: %T", vmessConfigs)
	}
	if len(vmessConfigs) != 1 {
		return nil, fmt.Errorf("unexpected amount of vmess configs: %d", len(vmessConfigs))
	}

	vmessConfig := vmessConfigs[0]
	port, err := strconv.ParseUint(vmessConfig.Port, 10, 16)
	if err != nil {
		return nil, err
	}

	aid, err := strconv.Atoi(vmessConfig.AlterID)
	if err != nil {
		return nil, err
	}

	security := "auto"
	if vmessConfig.Encryption != "" {
		security = vmessConfig.Encryption
	}
	transport, err := buildSingBoxOutboundTransport(vmessConfig)
	if err != nil {
		return nil, err
	}
	return &option.Outbound{
		Type: constant.TypeVMess,
		Tag:  vmessConfig.Name,
		Options: option.VMessOutboundOptions{
			UUID: vmessConfig.UUID,
			ServerOptions: option.ServerOptions{
				Server:     vmessConfig.Server,
				ServerPort: uint16(port),
			},
			Security: security,
			AlterId:  aid,
			OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
				TLS: buildSingBoxOutboundTLS(vmessConfig),
			},
			Transport: transport,
		},
	}, nil
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
	default:
		return nil, fmt.Errorf("unsupported outbound type: %s", outbound.Type)
	}
}

func buildSingBoxOutboundTLS(config model.VMess) *option.OutboundTLSOptions {
	if config.Security != "tls" {
		return nil
	}

	options := &option.OutboundTLSOptions{
		Enabled:  true,
		Insecure: config.AllowInsecure,
	}

	if config.SNI != "" {
		options.ServerName = config.SNI
	}
	if config.ALPN != "" {
		alpn := strings.FieldsFunc(string(config.ALPN), func(r rune) bool {
			return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ','
		})
		options.ALPN = alpn
	}

	if config.Certificates != "" {
		options.Certificate = badoption.Listable[string]{config.Certificates}
	}

	fp := config.UTLSFingerPrint
	if config.RealityPubKey != "" {
		options.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: config.RealityPubKey,
			ShortID:   config.RealityShortID,
		}
		if fp == "" {
			fp = "chrome"
		}
	}
	if fp != "" {
		options.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fp,
		}
	}
	if config.EnableECH {
		options.ECH = &option.OutboundECHOptions{
			Enabled: true,
		}
		if config.ECHConfig != "" {
			options.ECH.Config = strings.Split(config.ECHConfig, "\n")
		}
	}

	return options
}

func buildSingBoxOutboundTransport(config model.VMess) (*option.V2RayTransportOptions, error) {
	switch config.Type {
	case "ws":
		headers := make(badoption.HTTPHeader)

		if config.Host != "" {
			headers["Host"] = badoption.Listable[string]{config.Host}
		}

		options := &option.V2RayTransportOptions{
			Type: "ws",
			WebsocketOptions: option.V2RayWebsocketOptions{
				Headers: headers,
			},
		}

		if strings.Contains(config.Path, "?ed=") {
			options.WebsocketOptions.Path = config.Path[0:strings.Index(config.Path, "?ed=")]
			maxEarlyData := uint32(2048)
			if config.Path[strings.Index(config.Path, "?ed=")+4:] != "" {
				ed, err := strconv.ParseUint(config.Path[strings.Index(config.Path, "?ed=")+4:], 10, 32)
				if err != nil {
					return nil, fmt.Errorf("couldn't parse max early data: %w", err)
				}
				maxEarlyData = uint32(ed)
			}

			options.WebsocketOptions.MaxEarlyData = uint32(maxEarlyData)
			options.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
		} else {
			options.WebsocketOptions.Path = "/"
			if config.Path != "" {
				options.WebsocketOptions.Path = config.Path
			}
		}

		if config.WSMaxEarlyData > 0 {
			options.WebsocketOptions.MaxEarlyData = uint32(config.WSMaxEarlyData)
		}

		if config.EarlyDataHeaderName != "" {
			options.WebsocketOptions.EarlyDataHeaderName = config.EarlyDataHeaderName
		}

		return options, nil
	case "http":
		options := &option.V2RayTransportOptions{
			Type: "http",
			HTTPOptions: option.V2RayHTTPOptions{
				Path: "/",
			},
		}

		if config.Security != "tls" {
			options.HTTPOptions.Method = "GET"
		}
		if config.Host != "" {
			options.HTTPOptions.Host = strings.Split(config.Host, ",")
		}
		if config.Path != "" {
			options.HTTPOptions.Path = config.Path
		}
		return options, nil
	case "quic":
		return &option.V2RayTransportOptions{
			Type:        "quic",
			QUICOptions: option.V2RayQUICOptions{},
		}, nil
	case "grpc":
		return &option.V2RayTransportOptions{
			Type: "grpc",
			GRPCOptions: option.V2RayGRPCOptions{
				ServiceName: config.Path,
			},
		}, nil
	case "httpupgrade":
		return &option.V2RayTransportOptions{
			Type: "httpupgrade",
			HTTPUpgradeOptions: option.V2RayHTTPUpgradeOptions{
				Host: config.Host,
				Path: config.Path,
			},
		}, nil
	default:
		return nil, nil
	}
}
