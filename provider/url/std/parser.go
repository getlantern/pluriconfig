// Package std parses the standard format VMESS configuration, it can also be
// used for parsing vless configuration since they share a similar config pattern
package std

import (
	"context"
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
	return string(model.ProviderURLVMessStd)
}

// Parse parses the given data into a Config object.
func (p parser) Parse(ctx context.Context, data []byte) (*model.AnyConfig, error) {
	lines := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == '\n' || r == '\t' || r == ','
	})
	vmessConfigs := make([]model.VMess, 0)
	for _, line := range lines {
		providedURL, err := url.Parse(line)
		if err != nil {
			return nil, err
		}

		password, exists := providedURL.User.Password()
		if !exists {
			return nil, fmt.Errorf("invalid vmess std config")
		}
		protocol := providedURL.User.Username()
		config := model.VMess{
			ServerOptions: model.ServerOptions{
				Server: providedURL.Hostname(),
				Port:   providedURL.Port(),
			},
			Name: providedURL.Fragment,
			Type: protocol,
		}
		if strings.Contains(providedURL.Scheme, "vless") {
			config.AlterID = ""
			config.UUID = password
		} else {
			splitPassword := strings.Split(password, "-")
			if len(splitPassword) < 4 {
				return nil, fmt.Errorf("invalid uuid set in password")
			}
			config.AlterID = splitPassword[len(splitPassword)-1]
			config.UUID = strings.Join(splitPassword[0:len(splitPassword)-2], "-")
		}

		queryParams := providedURL.Query()
		if strings.HasSuffix(protocol, "+tls") {
			config.Security = "tls"
			protocol = protocol[0 : len(protocol)-4]
			if queryParams.Has("tlsServerName") && queryParams.Get("tlsServerName") != "" {
				config.SNI = queryParams.Get("tlsServerName")
			}
		}

		switch protocol {
		case "http":
			if queryParams.Has("path") {
				config.Path = queryParams.Get("path")
			}
			if queryParams.Has("host") {
				splitHostValues := strings.Split(queryParams.Get("host"), "|")
				config.Host = strings.Join(splitHostValues, ",")
			}
		case "ws", "httpupgrade":
			if queryParams.Has("path") {
				config.Path = queryParams.Get("path")
			}
			if queryParams.Has("host") {
				config.Host = queryParams.Get("host")
			}
		case "grpc":
			if queryParams.Has("serviceName") {
				config.Path = queryParams.Get("serviceName")
			}
		}
		vmessConfigs = append(vmessConfigs, config)
	}
	return &model.AnyConfig{
		Type:    model.ProviderURLVMessStd,
		Options: vmessConfigs,
	}, nil
}

func (p parser) Serialize(ctx context.Context, config *model.AnyConfig) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
