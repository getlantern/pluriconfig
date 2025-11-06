// Package qrcode parse the VMess data based on the qrcode json format into a common model.VMess object
package qrcode

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
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
	return string(model.ProviderURLVMessQRCode)
}

// Parse parses the given data into a Config object.
func (p parser) Parse(ctx context.Context, data []byte) (*model.AnyConfig, error) {
	lines := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == '\n' || r == '\t'
	})
	vmessConfigs := make([]model.VMess, 0)
	for _, line := range lines {
		parsedURL, err := url.Parse(line)
		if err != nil {
			return nil, err
		}
		decodedData, err := base64.StdEncoding.DecodeString(parsedURL.Host)
		if err != nil {
			return nil, err
		}
		var vmessConfig model.VMessQRCode
		if err := json.Unmarshal(decodedData, &vmessConfig); err != nil {
			return nil, fmt.Errorf("couldn't parse vmess json: %w", err)
		}

		if vmessConfig.Addr == "" ||
			vmessConfig.Port == "" ||
			vmessConfig.ID == "" ||
			vmessConfig.Net == "" {
			return nil, fmt.Errorf("invalid vmess config")
		}

		data := model.VMess{
			Name: vmessConfig.PS,
			ServerOptions: model.ServerOptions{
				Server: vmessConfig.Addr,
				Port:   vmessConfig.Port,
			},
			Encryption: vmessConfig.Security,
			UUID:       vmessConfig.ID,
			AlterID:    vmessConfig.Aid,
			Type:       vmessConfig.Net,
			Host:       vmessConfig.Host,
			Path:       vmessConfig.Path,
		}

		if data.Type == "tcp" && vmessConfig.Type == "http" {
			data.Type = "http"
		}

		if vmessConfig.TLS == "tls" || vmessConfig.TLS == "reality" {
			data.Security = "tls"
			data.SNI = vmessConfig.Sni
			if data.SNI == "" {
				data.SNI = vmessConfig.Host
			}
			data.ALPN = vmessConfig.ALPN
			data.UTLSFingerPrint = vmessConfig.Fp
		}
		vmessConfigs = append(vmessConfigs, data)
	}

	return &model.AnyConfig{
		Type:    model.ProviderURLVMessQRCode,
		Options: vmessConfigs,
	}, nil
}

func (p parser) Serialize(ctx context.Context, config *model.AnyConfig) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
