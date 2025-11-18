// Package kitsunebi parses the VMess data with the kitsunebi format into a common model.VMess object
// Example:
// vmess://YXV0bzo1YWY1ZDBlYy02ZWEwLTNjNDMtOTNkYi1jYTMwMDg1MDNiZGJAMTgzLjIzMi41Ni4xNjE6MTIwMg
// ?remarks=*%F0%9F%87%AF%F0%9F%87%B5JP%20-355%20TG@moon365free&obfsParam=%7B%22Host%22:%22183.232.56.161%22%7D&path=/v2ray&obfs=websocket&alterId=0
package kitsunebi

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
	return string(model.ProviderURLVMessKitsunebi)
}

// Parse parses the given data into a Config object.
func (p parser) Parse(ctx context.Context, data []byte) (*model.AnyConfig, error) {
	lines := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ','
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
		arr1 := strings.Split(string(decodedData), "@")
		if len(arr1) != 2 {
			return nil, fmt.Errorf("invalid kitsunebi format")
		}

		arr21 := strings.Split(arr1[0], ":")
		arr22 := strings.Split(arr1[1], ":")
		if len(arr21) != 2 && len(arr22) != 2 {
			return nil, fmt.Errorf("invalid kitsunebi format")
		}

		data := model.VMess{
			ServerOptions: model.ServerOptions{
				Server: arr22[0],
				Port:   arr22[1],
			},
			UUID:       arr21[1],
			Encryption: arr21[0],
		}

		queryParams := parsedURL.Query()
		if len(queryParams) == 0 {
			vmessConfigs = append(vmessConfigs, data)
			continue
		}

		data.Name = queryParams.Get("remarks")
		data.AlterID = queryParams.Get("alterId")
		data.Path = queryParams.Get("path")
		data.Security = "tls"

		if insecure := queryParams.Get("allowInsecure"); insecure != "" {
			data.AllowInsecure = insecure == "1" || insecure == "true"
		}

		if queryParams.Has("obfs") {
			val := queryParams.Get("obfs")
			data.Type = strings.ReplaceAll(strings.ReplaceAll(val, "websocket", "ws"), "none", "tcp")
			if data.Type == "ws" {
				for _, v := range queryParams["obfsParam"] {
					if strings.HasPrefix(v, "{") {
						var param obfsParam
						if err := json.Unmarshal([]byte(v), &param); err == nil {
							data.Host = param.Host
						}
					} else if data.Security == "tls" {
						data.SNI = v
					}
				}
			}
		}
		vmessConfigs = append(vmessConfigs, data)
	}

	return &model.AnyConfig{
		Type:    model.ProviderURLVMessKitsunebi,
		Options: vmessConfigs,
	}, nil
}

type obfsParam struct {
	Host string `json:"Host"`
}

// Serialize serializes the given Config object into a kitsunebi format.
func (p parser) Serialize(ctx context.Context, config *model.AnyConfig) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}
