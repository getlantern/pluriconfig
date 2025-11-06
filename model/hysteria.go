package model

type Hysteria struct {
	Name string
	ServerOptions
	ProtocolVersion int

	ServerPorts string `yaml:"ports"`

	AuthPayload         string
	Obfuscation         string
	SNI                 string
	CaText              string
	UploadMbps          int  `yaml:"up"`
	DownloadMbps        int  `yaml:"down"`
	AllowInsecure       bool `yaml:"skip-cert-verify"`
	StreamReceiveWindow int
	ConnReceiveWindow   int
	DisableMTUDiscovery bool
	HopInterval         int

	ALPN string

	AuthPayloadType int
	Protocol        int
}
