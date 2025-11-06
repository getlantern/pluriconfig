// Package csv parses the CSV data into a common model.VMess object
package csv

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
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
	return string(model.ProviderURLVMessCSV)
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

		if strings.Contains(parsedURL.Scheme, "vmess") && !strings.Contains(string(decodedData), "= vmess") {
			return nil, fmt.Errorf("protocol or url format not supported")
		}
		r := csv.NewReader(strings.NewReader(string(decodedData)))
		for {
			args, err := r.Read()
			if err == io.EOF {
				break
			}

			if err != nil {
				return nil, fmt.Errorf("failed to read CSV line: %w", err)
			}

			data := model.VMess{
				ServerOptions: model.ServerOptions{
					Server: args[1],
					Port:   args[2],
				},
				Encryption: args[3],
				UUID:       strings.ReplaceAll(args[4], "\"", ""),
			}

			for _, val := range args[5:] {
				switch {
				case val == "over-tls=true":
					data.Security = "tls"
				case strings.HasPrefix(val, "tls-host="):
					data.Host = strings.TrimPrefix(val, "tls-host=")
				case strings.HasPrefix(val, "obfs="):
					data.Type = strings.TrimPrefix(val, "obfs=")
				case strings.HasPrefix(val, "obfs-path=") || strings.Contains(val, "Host:"):
					if v, ok := extractBetween(val, "obfs-path=\"", "\"obfs"); ok {
						data.Path = v
					}

					if v, ok := extractBetween(val, "Host:", "["); ok {
						data.Host = v
					}
				}
			}
			vmessConfigs = append(vmessConfigs, data)
		}
	}
	return &model.AnyConfig{
		Type:    model.ProviderURLVMessCSV,
		Options: vmessConfigs,
	}, nil
}

func extractBetween(data, beginsWith, endsWith string) (string, bool) {
	i := strings.Index(data, beginsWith)
	if i < 0 {
		return "", false
	}

	start := i + len(beginsWith)
	j := strings.Index(data[start:], endsWith)
	if j < 0 {
		return "", false
	}

	return data[start : start+j], true
}

// Serialize serializes the given Config object into a csv format.
func (p parser) Serialize(ctx context.Context, config *model.AnyConfig) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
