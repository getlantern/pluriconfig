// Package ducksoft implements a ducksoft parser that can be used for parsing
// vmess, vless, and trojan configurations by returning a VMESS data structure.
// Note that trojan configurations must retrieve the password from the URL username.
// URL Example:
// protocol://$(uuid)@remote-host:remote-port?<protocol-specific fields><transport-specific fields><tls-specific fields>#$(descriptive-text)
package ducksoft

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

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
	return string(model.ProviderURLVMessDucksoft)
}

// Parse parses the given data into a Config object.
func (p parser) Parse(ctx context.Context, data []byte) (*model.AnyConfig, error) {
	lines := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == '\n' || r == ','
	})
	vmessConfigs := make([]model.VMess, 0)
	for _, line := range lines {
		providedURL, err := url.Parse(line)
		if err != nil {
			return nil, err
		}
		isTrojan := strings.Contains(providedURL.Scheme, "trojan")
		isVLESS := strings.Contains(providedURL.Scheme, "vless")

		var vmessConfig model.VMess
		if isVLESS {
			vmessConfig.AlterID = ""
		}

		vmessConfig.ServerOptions = model.ServerOptions{
			Server: providedURL.Hostname(),
			Port:   providedURL.Port(),
		}
		vmessConfig.Name = providedURL.EscapedFragment()
		// if it's trojan config, we need to retrieve the password from the url username
		if !isTrojan {
			vmessConfig.UUID = providedURL.User.Username()
		}

		if providedURL.Path != "" {
			vmessConfig.Path = providedURL.Path
		}

		queryParams := providedURL.Query()
		vmessConfig.Type = "tcp"
		if queryParams.Has("type") {
			vmessConfig.Type = queryParams.Get("type")
		}

		vmessConfig.Security = queryParams.Get("security")
		if vmessConfig.Security == "" {
			if isTrojan {
				vmessConfig.Security = "tls"
			} else {
				vmessConfig.Security = "none"
			}
		}

		if vmessConfig.Security == "tls" || vmessConfig.Security == "reality" {
			vmessConfig.Security = "tls"
			if queryParams.Has("allowInsecure") {
				allowInsecureVal := queryParams.Get("allowInsecure")
				vmessConfig.AllowInsecure = allowInsecureVal == "1" || allowInsecureVal == "true"
			}
			if queryParams.Has("sni") {
				vmessConfig.SNI = queryParams.Get("sni")
			}
			if queryParams.Has("host") {
				if vmessConfig.SNI == "" {
					vmessConfig.SNI = queryParams.Get("host")
				}
			}
			if queryParams.Has("alpn") {
				vmessConfig.ALPN = queryParams.Get("alpn")
			}
			if queryParams.Has("cert") {
				vmessConfig.Certificates = queryParams.Get("cert")
			}
			if queryParams.Has("pbk") {
				vmessConfig.RealityPubKey = queryParams.Get("pbk")
			}
			if queryParams.Has("sid") {
				vmessConfig.RealityShortID = queryParams.Get("sid")
			}
		}

		switch vmessConfig.Type {
		case "http", "httpupgrade":
			if queryParams.Has("path") {
				vmessConfig.Path = queryParams.Get("path")
			}
			if queryParams.Has("host") {
				vmessConfig.Host = queryParams.Get("host")
			}
		case "ws":
			if queryParams.Has("path") {
				vmessConfig.Path = queryParams.Get("path")
			}
			if queryParams.Has("host") {
				vmessConfig.Host = queryParams.Get("host")
			}
			if queryParams.Has("ed") {
				var err error
				vmessConfig.WSMaxEarlyData, err = strconv.Atoi(queryParams.Get("ed"))
				if err != nil {
					return nil, err
				}

				if queryParams.Has("eh") {
					vmessConfig.EarlyDataHeaderName = queryParams.Get("eh")
				}
			}
		case "grpc":
			if queryParams.Has("serviceName") {
				vmessConfig.Path = queryParams.Get("serviceName")
			}
		}

		if !isVLESS && queryParams.Has("encryption") {
			vmessConfig.Encryption = queryParams.Get("encryption")
		}

		if queryParams.Has("packetEncoding") {
			switch queryParams.Get("packetEncoding") {
			case "packet":
				vmessConfig.PacketEncoding = 1
			case "xudp":
				vmessConfig.PacketEncoding = 2
			}
		}

		if isVLESS && queryParams.Has("flow") {
			vmessConfig.Encryption = strings.ReplaceAll(queryParams.Get("flow"), "-udp443", "")
		}

		if queryParams.Has("fp") {
			vmessConfig.UTLSFingerPrint = queryParams.Get("fp")
		}
		vmessConfigs = append(vmessConfigs, vmessConfig)
	}
	return &model.AnyConfig{
		Type:    model.ProviderURLVMessDucksoft,
		Options: vmessConfigs,
	}, nil
}

func (p parser) Serialize(ctx context.Context, config *model.AnyConfig) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
