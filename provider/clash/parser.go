// Package clash implements a clash parser.
// A documentation about the configuration definition can be found at
// https://en.clash.wiki/configuration/outbound.html
package clash

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/getlantern/pluriconfig"
	"github.com/getlantern/pluriconfig/model"
	"github.com/goccy/go-yaml"
	"github.com/sagernet/sing-box/option"
)

type parser struct{}

func init() {
	if err := pluriconfig.Register(parser{}); err != nil {
		panic(err)
	}
}

func (p parser) Name() string {
	return string(model.ProviderClash)
}

// Parse parses the given data into a Config object.
func (p parser) Parse(ctx context.Context, data []byte) (*model.AnyConfig, error) {
	var cfg model.ClashConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal clash config: %w", err)
	}

	return &model.AnyConfig{
		Type:    model.ProviderClash,
		Options: cfg.Proxies,
	}, nil
}

// Serialize serializes the given Config object into clash proxies list.
func (p parser) Serialize(ctx context.Context, config *model.AnyConfig) ([]byte, error) {
	var proxies []model.Outbound
	var ok bool
	switch config.Type {
	case model.ProviderClash:
		if proxies, ok = config.Options.([]model.Outbound); !ok {
			return nil, fmt.Errorf("invalid options type: %T", config.Options)
		}
	case model.ProviderURL:
		proxies = []model.Outbound{}
		urls, ok := config.Options.([]url.URL)
		if !ok {
			return nil, fmt.Errorf("invalid options type: %T", config.Options)
		}
		for _, url := range urls {
			proxy, err := convertURLToClashProxy(url)
			if err != nil {
				return nil, fmt.Errorf("failed to convert url to clash proxy: %w", err)
			}
			proxies = append(proxies, proxy)
		}
	case model.ProviderSingBox:
		proxies = []model.Outbound{}
		singBoxOpts, ok := config.Options.(model.SingBoxOptions)
		if !ok {
			return nil, fmt.Errorf("invalid options type: %T", config.Options)
		}
		for _, outbound := range singBoxOpts.Outbounds {
			proxy, err := convertSingBoxToClashProxy(outbound)
			if err != nil {
				return nil, fmt.Errorf("failed to convert sing-box outbound to clash proxy: %w", err)
			}
			proxies = append(proxies, proxy)
		}

	default:
		return nil, fmt.Errorf("unsupported config type: %s", config.Type)
	}

	data, err := yaml.Marshal(proxies)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal clash proxies: %w", err)
	}
	return data, nil
}

func convertSingBoxToClashProxy(opt option.Outbound) (model.Outbound, error) {
	switch opt.Type {
	case "shadowsocks":
		return convertSingBoxShadowsocksToClashProxy(opt)
	case "trojan":
		return convertSingBoxTrojanToClashProxy(opt)
	case "vmess":
		return convertSingBoxVMessToClashProxy(opt)
	default:
		return model.Outbound{}, fmt.Errorf("unsupported sing-box outbound type: %s", opt.Type)
	}
}

func convertURLToClashProxy(url url.URL) (model.Outbound, error) {
	switch url.Scheme {
	case "ss":
		return outboundFromShadowsocksURL(url)
	case "ssr":
		return outboundFromShadowsocksRURL(url)
	case "vmess":
		return outboundFromVmessURL(url)
	case "trojan":
		return outboundFromTrojanURL(url)
	default:
		return model.Outbound{}, fmt.Errorf("unsupported url scheme: %s", url.Scheme)
	}
}

func outboundFromShadowsocksURL(url url.URL) (model.Outbound, error) {
	decodedUsername, err := base64.StdEncoding.DecodeString(url.User.Username())
	if err != nil {
		return model.Outbound{}, fmt.Errorf("couldn't decode shadowsocks username: %w", err)
	}
	splitUsername := strings.Split(string(decodedUsername), ":")
	if len(splitUsername) != 2 {
		return model.Outbound{}, fmt.Errorf("couldn't parse shadowsocks method and password from username")
	}

	return model.Outbound{
		Name: url.Fragment,
		Type: url.Scheme,
		Options: model.ShadowsocksOutboundOptions{
			ServerOptions: model.ServerOptions{
				Server: url.Hostname(),
				Port:   url.Port(),
			},
			Cipher:   splitUsername[0],
			Password: splitUsername[1],
			UDP:      url.Query().Has("udp"),
		},
	}, nil
}

func outboundFromShadowsocksRURL(url url.URL) (model.Outbound, error) {
	outbound, err := outboundFromShadowsocksURL(url)
	if err != nil {
		return model.Outbound{}, err
	}

	ssrOptions := model.ShadowsocksROutboundOptions{
		ShadowsocksOutboundOptions: outbound.Options.(model.ShadowsocksOutboundOptions),
		OBFS:                       url.Query().Get("obfs"),
		Protocol:                   url.Query().Get("protocol"),
		OBFSParam:                  url.Query().Get("obfs-param"),
		ProtocolParam:              url.Query().Get("protocol-param"),
	}
	outbound.Options = ssrOptions
	return outbound, nil
}

func outboundFromVmessURL(url url.URL) (model.Outbound, error) {
	jsonEncoded, err := base64.StdEncoding.DecodeString(url.Opaque)
	if err != nil {
		return model.Outbound{}, fmt.Errorf("couldn't parse decode vmess base64: %w", err)
	}

	var vmessConfig model.VMESSConfig
	if err := json.Unmarshal(jsonEncoded, &vmessConfig); err != nil {
		return model.Outbound{}, fmt.Errorf("couldn't parse vmess json: %w", err)
	}
	v2rOpts := model.V2RTransportOpts{
		Type:        vmessConfig.Net,
		Host:        vmessConfig.Host,
		Path:        vmessConfig.Path,
		ServiceName: vmessConfig.Host,
	}
	aid, err := strconv.Atoi(vmessConfig.Aid)
	if err != nil {
		return model.Outbound{}, fmt.Errorf("couldn't parse alter id from vmess config: %w", err)
	}

	options := model.VMESSOutboundOptions{
		ServerOptions: model.ServerOptions{
			Server: vmessConfig.Addr,
			Port:   vmessConfig.Port,
		},
		UUID:    vmessConfig.ID,
		AlterID: aid,
		Cipher:  vmessConfig.Security,
	}

	switch v2rOpts.Type {
	case "http":
		options.HTTPOpts = &model.VMESSOutboundHTTPOpts{
			Path: []string{v2rOpts.Path},
		}
	case "h2":
		options.H2Opts = &model.VMESSOutboundH2Opts{
			Host: []string{v2rOpts.Host},
			Path: v2rOpts.Path,
		}
	case "grpc":
		options.GRPCOpts = &model.VMESSOutboundGRPCOpts{
			ServiceName: v2rOpts.ServiceName,
		}
	}

	if vmessConfig.TLS == "tls" {
		options.TLS = true
		options.ServerName = vmessConfig.Sni
	}

	return model.Outbound{
		Name:    url.Fragment,
		Type:    url.Scheme,
		Options: options,
	}, nil
}

func outboundFromTrojanURL(url url.URL) (model.Outbound, error) {
	options := model.TrojanOutboundOptions{
		ServerOptions: model.ServerOptions{
			Server: url.Hostname(),
			Port:   url.Port(),
		},
		Password:       url.User.Username(),
		SNI:            url.Query().Get("sni"),
		UDP:            url.Query().Has("udp"),
		ALPN:           []string{url.Query().Get("alpn")},
		SkipCertVerify: url.Query().Has("allowInsecure"),
	}
	queryParams := url.Query()
	v2rTransportOpts := model.V2RTransportOpts{
		Type:        queryParams.Get("type"),
		Path:        queryParams.Get("path"),
		ServiceName: queryParams.Get("serviceName"),
	}

	switch v2rTransportOpts.Type {
	case "grpc":
		options.GRPCOpts = &model.TrojanOutboundGRPCOpts{
			ServiceName: v2rTransportOpts.ServiceName,
		}
	case "ws":
		options.WSOpts = &model.TrojanOutboundWSOpts{
			Path: v2rTransportOpts.Path,
		}
	}

	return model.Outbound{
		Name:    url.Fragment,
		Type:    url.Scheme,
		Options: options,
	}, nil
}

func convertSingBoxShadowsocksToClashProxy(opt option.Outbound) (model.Outbound, error) {
	socksOptions, ok := opt.Options.(option.ShadowsocksOutboundOptions)
	if !ok {
		return model.Outbound{}, fmt.Errorf("invalid shadowsocks options type: %T", opt.Options)
	}

	return model.Outbound{
		Name: opt.Tag,
		Type: "shadowsocks",
		Options: model.ShadowsocksOutboundOptions{
			ServerOptions: model.ServerOptions{
				Server: socksOptions.Server,
				Port:   fmt.Sprintf("%d", socksOptions.ServerPort),
			},
			Cipher:   socksOptions.Method,
			Password: socksOptions.Password,
			UDP:      socksOptions.UDPOverTCP != nil,
			Plugin:   socksOptions.Plugin,
		},
	}, nil
}

func convertSingBoxTrojanToClashProxy(opt option.Outbound) (model.Outbound, error) {
	providedTrojanOptions, ok := opt.Options.(option.TrojanOutboundOptions)
	if !ok {
		return model.Outbound{}, fmt.Errorf("invalid trojan options type: %T", opt.Options)
	}

	trojanOptions := model.TrojanOutboundOptions{
		ServerOptions: model.ServerOptions{
			Server: providedTrojanOptions.Server,
			Port:   fmt.Sprintf("%d", providedTrojanOptions.ServerPort),
		},
		Password: providedTrojanOptions.Password,
	}

	if providedTrojanOptions.TLS != nil && providedTrojanOptions.TLS.Enabled {
		trojanOptions.SkipCertVerify = providedTrojanOptions.TLS.Insecure
		trojanOptions.SNI = providedTrojanOptions.TLS.ServerName
		trojanOptions.ALPN = providedTrojanOptions.TLS.ALPN
	}

	if providedTrojanOptions.Transport != nil {
		switch providedTrojanOptions.Transport.Type {
		case "grpc":
			trojanOptions.GRPCOpts = &model.TrojanOutboundGRPCOpts{
				ServiceName: providedTrojanOptions.Transport.GRPCOptions.ServiceName,
			}
		case "ws":
			trojanOptions.WSOpts = &model.TrojanOutboundWSOpts{
				Path:    providedTrojanOptions.Transport.WebsocketOptions.Path,
				Headers: providedTrojanOptions.Transport.WebsocketOptions.Headers.Build(),
			}
		}
	}

	return model.Outbound{
		Name:    opt.Tag,
		Type:    "trojan",
		Options: trojanOptions,
	}, nil
}

func convertSingBoxVMessToClashProxy(opt option.Outbound) (model.Outbound, error) {
	providedVMessOptions, ok := opt.Options.(option.VMessOutboundOptions)
	if !ok {
		return model.Outbound{}, fmt.Errorf("invalid vmess options type: %T", opt.Options)
	}

	vmessOptions := model.VMESSOutboundOptions{
		ServerOptions: model.ServerOptions{
			Server: providedVMessOptions.Server,
			Port:   fmt.Sprintf("%d", providedVMessOptions.ServerPort),
		},
		UUID:    providedVMessOptions.UUID,
		AlterID: providedVMessOptions.AlterId,
		Cipher:  providedVMessOptions.Security,
	}

	if providedVMessOptions.TLS != nil && providedVMessOptions.TLS.Enabled {
		vmessOptions.TLS = true
		vmessOptions.ServerName = providedVMessOptions.TLS.ServerName
		vmessOptions.SkipCertVerify = providedVMessOptions.TLS.Insecure
	}

	if providedVMessOptions.Transport != nil {
		switch providedVMessOptions.Transport.Type {
		case "http":
			vmessOptions.HTTPOpts = &model.VMESSOutboundHTTPOpts{
				Method:  providedVMessOptions.Transport.HTTPOptions.Method,
				Path:    []string{providedVMessOptions.Transport.HTTPOptions.Path},
				Headers: providedVMessOptions.Transport.HTTPOptions.Headers.Build(),
			}
		case "httpupgrade":
			vmessOptions.H2Opts = &model.VMESSOutboundH2Opts{
				Host: []string{providedVMessOptions.Transport.HTTPUpgradeOptions.Host},
				Path: providedVMessOptions.Transport.HTTPUpgradeOptions.Path,
			}
		case "ws":
			vmessOptions.WSOpts = &model.VMESSOutboundWSOpts{
				Path:                providedVMessOptions.Transport.WebsocketOptions.Path,
				Headers:             providedVMessOptions.Transport.WebsocketOptions.Headers.Build(),
				MaxEarlyData:        int(providedVMessOptions.Transport.WebsocketOptions.MaxEarlyData),
				EarlyDataHeaderName: providedVMessOptions.Transport.WebsocketOptions.EarlyDataHeaderName,
			}
		case "grpc":
			vmessOptions.GRPCOpts = &model.VMESSOutboundGRPCOpts{
				ServiceName: providedVMessOptions.Transport.GRPCOptions.ServiceName,
			}
		}
	}
	return model.Outbound{
		Name:    opt.Tag,
		Type:    "vmess",
		Options: vmessOptions,
	}, nil
}
