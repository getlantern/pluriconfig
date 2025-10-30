package clash

import (
	"context"
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/getlantern/pluriconfig/model"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/require"
)

func TestParser_Name(t *testing.T) {
	p := parser{}
	require.Equal(t, string(model.ProviderClash), p.Name())
}

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		yamlInput string
		wantType  model.Provider
		wantErr   bool
	}{
		{
			name: "valid config",
			yamlInput: `
proxies:
  - name: "proxy1"
    type: "shadowsocks"
    server: "1.2.3.4"
    port: 8388
    cipher: "aes-256-gcm"
    password: "pass"
`,
			wantType: model.ProviderClash,
			wantErr:  false,
		},
		{
			name:      "invalid yaml",
			yamlInput: `proxies: [`,
			wantErr:   true,
		},
	}

	p := parser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := p.Parse(context.Background(), []byte(tt.yamlInput))
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				require.Equal(t, tt.wantType, cfg.Type)
				require.NotNil(t, cfg.Options)
			}
		})
	}
}

func TestParser_Serialize(t *testing.T) {
	p := parser{}
	type args struct {
		cfg *model.AnyConfig
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Clash Outbounds",
			args: args{
				cfg: &model.AnyConfig{
					Type: model.ProviderClash,
					Options: []model.Outbound{
						{
							Name: "proxy1",
							Type: "shadowsocks",
							Options: model.ShadowsocksOutboundOptions{
								ServerOptions: model.ServerOptions{
									Server: "1.2.3.4",
									Port:   "8388",
								},
								Cipher:   "aes-256-gcm",
								Password: "pass",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "URL Outbounds",
			args: args{
				cfg: &model.AnyConfig{
					Type: model.ProviderURL,
					Options: []url.URL{
						{
							Scheme:   "ss",
							User:     url.User(base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pass"))),
							Host:     "1.2.3.4:8388",
							Fragment: "proxy1",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "SingBox Outbounds",
			args: args{
				cfg: &model.AnyConfig{
					Type: model.ProviderSingBox,
					Options: model.SingBoxOptions{
						Outbounds: []option.Outbound{
							{
								Type: "shadowsocks",
								Tag:  "proxy1",
								Options: option.ShadowsocksOutboundOptions{
									ServerOptions: option.ServerOptions{
										Server:     "1.2.3.4",
										ServerPort: 8388,
									},
									Method:   "aes-256-gcm",
									Password: "pass",
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid Type",
			args: args{
				cfg: &model.AnyConfig{
					Type:    "invalid",
					Options: nil,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := p.Serialize(context.Background(), tt.args.cfg)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotEmpty(t, data)
			}
		})
	}
}
