package model

type ClashConfig struct {
	Proxies []Outbound `yaml:"proxies"`
}

type Outbound struct {
	Name          string `yaml:"name"`
	Type          string `yaml:"type"`
	InterfaceName string `yaml:"interface-name,omitempty"`
	RoutingMark   int    `yaml:"routing-mark,omitempty"`
	Options       any    `yaml:",inline"`
}

type ServerOptions struct {
	Server string `yaml:"server"`
	Port   string `yaml:"port"`
}

type ShadowsocksOutboundOptions struct {
	ServerOptions `yaml:",inline"`
	Cipher        string                `yaml:"cipher"`
	Password      string                `yaml:"password"`
	UDP           bool                  `yaml:"udp,omitempty"`
	Plugin        string                `yaml:"plugin,omitempty"`
	PluginOpts    ShadowsocksPluginOpts `yaml:"plugin-opts,omitempty"`
}

type ShadowsocksPluginOpts struct {
	Mode           string            `yaml:"mode,omitempty"`
	Host           string            `yaml:"host,omitempty"`
	TLS            bool              `yaml:"tls,omitempty"`
	SkipCertVerify bool              `yaml:"skip-cert-verify,omitempty"`
	Path           string            `yaml:"path,omitempty"`
	Mux            bool              `yaml:"mux,omitempty"`
	Header         map[string]string `yaml:"header,omitempty"`
}

type ShadowsocksROutboundOptions struct {
	ShadowsocksOutboundOptions `yaml:",inline"`
	OBFS                       string `yaml:"obfs,omitempty"`
	Protocol                   string `yaml:"protocol,omitempty"`
	OBFSParam                  string `yaml:"obfs-param,omitempty"`
	ProtocolParam              string `yaml:"protocol-param,omitempty"`
}

type VMESSOutboundOptions struct {
	ServerOptions  `yaml:",inline"`
	UUID           string                 `yaml:"uuid"`
	AlterID        int                    `yaml:"alterId,omitempty"`
	Cipher         string                 `yaml:"cipher,omitempty"`
	UDP            bool                   `yaml:"udp,omitempty"`
	TLS            bool                   `yaml:"tls,omitempty"`
	SkipCertVerify bool                   `yaml:"skip-cert-verify,omitempty"`
	ServerName     string                 `yaml:"server-name,omitempty"`
	Network        string                 `yaml:"network,omitempty"`
	WSOpts         *VMESSOutboundWSOpts   `yaml:"ws-opts,omitempty"`
	HTTPOpts       *VMESSOutboundHTTPOpts `yaml:"http-opts,omitempty"`
	H2Opts         *VMESSOutboundH2Opts   `yaml:"h2-opts,omitempty"`
	GRPCOpts       *VMESSOutboundGRPCOpts `yaml:"grpc-opts,omitempty"`
}

type VMESSOutboundWSOpts struct {
	Path                string              `yaml:"path,omitempty"`
	Headers             map[string][]string `yaml:"headers,omitempty"`
	MaxEarlyData        int                 `yaml:"max-early-data,omitempty"`
	EarlyDataHeaderName string              `yaml:"early-data-header-name,omitempty"`
}

type VMESSOutboundHTTPOpts struct {
	Method  string              `yaml:"method,omitempty"`
	Path    []string            `yaml:"path,omitempty"`
	Headers map[string][]string `yaml:"headers,omitempty"`
}

type VMESSOutboundH2Opts struct {
	Host []string `yaml:"host,omitempty"`
	Path string   `yaml:"path,omitempty"`
}

type VMESSOutboundGRPCOpts struct {
	ServiceName string `yaml:"service-name,omitempty"`
}

type Socks5OutboundOptions struct {
	ServerOptions  `yaml:",inline"`
	Username       string `yaml:"username,omitempty"`
	Password       string `yaml:"password,omitempty"`
	TLS            bool   `yaml:"tls,omitempty"`
	SkipCertVerify bool   `yaml:"skip-cert-verify,omitempty"`
	UDP            bool   `yaml:"udp,omitempty"`
}

type HTTPOutboundOptions struct {
	ServerOptions `yaml:",inline"`
	Username      string `yaml:"username,omitempty"`
	Password      string `yaml:"password,omitempty"`
}

type TrojanOutboundOptions struct {
	ServerOptions  `yaml:",inline"`
	Password       string                  `yaml:"password"`
	UDP            bool                    `yaml:"udp,omitempty"`
	SNI            string                  `yaml:"sni,omitempty"`
	ALPN           []string                `yaml:"alpn,omitempty"`
	SkipCertVerify bool                    `yaml:"skip-cert-verify,omitempty"`
	GRPCOpts       *TrojanOutboundGRPCOpts `yaml:"grpc-opts,omitempty"`
	WSOpts         *TrojanOutboundWSOpts   `yaml:"ws-opts,omitempty"`
}

type TrojanOutboundGRPCOpts struct {
	ServiceName string `yaml:"service-name,omitempty"`
}

type TrojanOutboundWSOpts struct {
	Path    string              `yaml:"path,omitempty"`
	Headers map[string][]string `yaml:"headers,omitempty"`
}
