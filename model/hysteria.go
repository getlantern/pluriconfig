package model

type Hysteria struct {
	Name string
	ServerOptions
	ProtocolVersion int

	ServerPorts string

	AuthPayload         string
	Obfuscation         string
	SNI                 string
	CaText              string
	UploadMbps          int
	DownloadMbps        int
	AllowInsecure       bool
	StreamReceiveWindow int
	ConnReceiveWindow   int
	DisableMTUDiscovery bool
	HopInterval         int

	ALPN string

	AuthPayloadType int
	Protocol        int
}
