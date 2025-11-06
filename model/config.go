// Package model holds the data models used across the application.
package model

import "github.com/sagernet/sing-box/option"

// Config is a generic configuration struct that holds a type identifier and options of any type.
type Config[T any] struct {
	Type    Provider
	Options T
}

type AnyConfig = Config[any]

type Provider string

const (
	ProviderSingBox           Provider = "singbox"
	ProviderURL               Provider = "url"
	ProviderClash             Provider = "clash"
	ProviderURLVMessCSV       Provider = "vmess-csv"
	ProviderURLVMessQRCode    Provider = "vmess-qrcode"
	ProviderURLVMessKitsunebi Provider = "vmess-kitsunebi"
	ProviderURLVMessStd       Provider = "vmess-std"
	ProviderURLVMessDucksoft  Provider = "vmess-ducksoft"
)

// V2RTransportOpts holds options for V2Ray transport configuration.
type V2RTransportOpts struct {
	Type        string
	Host        string
	Path        string
	Method      string
	ServiceName string
	Headers     map[string][]string
}

// VMESSConfig holds the configuration for a VMESS protocol.
type VMESSConfig struct {
	Addr     string `json:"add"`
	Port     string `json:"port"`
	Aid      string `json:"aid"`
	ALPN     string `json:"alpn"`
	Host     string `json:"host"`
	ID       string `json:"id"`
	Net      string `json:"net"`
	Path     string `json:"path"`
	PS       string `json:"ps"`
	Security string `json:"scy"`
	Sni      string `json:"sni"`
	TLS      string `json:"tls"`
}

type SingBoxOptions struct {
	Outbounds []option.Outbound `json:"outbounds,omitempty"`
	Endpoints []option.Endpoint `json:"endpoints,omitempty"`
}
