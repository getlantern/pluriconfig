package singbox

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"testing"

	box "github.com/getlantern/lantern-box"
	"github.com/sagernet/sing-box/option"

	"github.com/getlantern/pluriconfig/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser_Parse(t *testing.T) {
	p := parser{}

	jsonData := []byte(`{
            "outbounds": [
                {
                    "type": "shadowsocks",
                    "tag": "ss-out",
                    "server": "127.0.0.1",
                    "server_port": 8388,
                    "method": "chacha20-ietf-poly1305",
                    "password": "randompasswordwith24char",
                    "network": "tcp"
                },
                {
                    "type": "anytls",
                    "tag": "anytls-out",
                    "server": "127.0.0.1",
                    "server_port": 443,
                    "password": "batatinhaQuandoNasceEspalhaARamaPeloChão",
                    "idle_session_check_interval": "30s",
                    "idle_session_timeout": "30s",
                    "min_idle_session": 60,
                    "tls": {
                        "enabled": true,
                        "server_name": "example.com",
                        "insecure": true,
                        "alpn": ["h1"],
                        "utls": {
                            "enabled": true,
                            "fingerprint": "chrome"
                        }
                    }
                }
            ],
        }`)

	cfg, err := p.Parse(box.BaseContext(), jsonData)
	require.NoError(t, err, "Parse() error")

	assert.Equal(t, model.ProviderSingBox, cfg.Type)
	assert.Len(t, cfg.Options.(model.SingBoxOptions).Outbounds, 2)
	assert.Equal(t, "shadowsocks", cfg.Options.(model.SingBoxOptions).Outbounds[0].Type)
	assert.Equal(t, "anytls", cfg.Options.(model.SingBoxOptions).Outbounds[1].Type)
}

func TestParser_Serialize(t *testing.T) {
	p := parser{}
	ctx := box.BaseContext()
	expectedSSConfig := `{"outbounds": [{"tag": "ss-out", "type": "shadowsocks", "server": "127.0.0.1", "server_port": 8388, "method": "chacha20-ietf-poly1305", "password": "randompasswordwith24char"}]}`
	ssURL := url.URL{
		Scheme:   "ss",
		User:     url.User(base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:randompasswordwith24char"))),
		Host:     "127.0.0.1:8388",
		Fragment: "ss-out",
	}
	password := "uuid"
	hostname := "127.0.0.1"
	port := "443"
	serverName := "randomServerName.com"
	tagName := "anytls-out"

	anytlsURL, err := url.Parse(fmt.Sprintf("anytls://%s@%s:%s/?insecure=1&sni=%s&fp=chrome#%s", password, hostname, port, serverName, tagName))
	require.NoError(t, err)
	expectedAnyTLSConfig := fmt.Sprintf(`{"outbounds": [{"tag": %q, "type": "anytls", "server": %q, "server_port": %s, "password": %q, "tls": {"enabled": true, "insecure": true, "server_name": %q, "utls": {"enabled": true, "fingerprint": "chrome"}}}]}`, tagName, hostname, port, password, serverName)

	ssOutbound := model.Outbound{
		Name: "ss-out",
		Type: "shadowsocks",
		Options: model.ShadowsocksOutboundOptions{
			ServerOptions: model.ServerOptions{
				Server: "127.0.0.1",
				Port:   "8388",
			},
			Cipher:   "chacha20-ietf-poly1305",
			Password: "randompasswordwith24char",
		},
	}
	type args struct {
		ctx context.Context
		cfg *model.AnyConfig
	}
	var tests = []struct {
		name      string
		assert    func(t *testing.T, got []byte, err error)
		givenArgs args
	}{
		{
			name: "should return an error when the config provider is not supported",
			assert: func(t *testing.T, got []byte, err error) {
				assert.Error(t, err)
				assert.Nil(t, got)
			},
			givenArgs: args{
				ctx: ctx,
				cfg: &model.AnyConfig{
					Type: "unsupported",
				},
			},
		},
		{
			name: "should serialize a valid sing-box config successfully",
			assert: func(t *testing.T, got []byte, err error) {
				require.NoError(t, err)
				assert.JSONEq(t, expectedSSConfig, string(got))
			},
			givenArgs: args{
				ctx: ctx,
				cfg: &model.AnyConfig{
					Type: model.ProviderSingBox,
					Options: model.SingBoxOptions{
						Outbounds: []option.Outbound{
							{
								Type: "shadowsocks",
								Tag:  "ss-out",
								Options: option.ShadowsocksOutboundOptions{
									ServerOptions: option.ServerOptions{
										Server:     "127.0.0.1",
										ServerPort: 8388,
									},
									Method:   "chacha20-ietf-poly1305",
									Password: "randompasswordwith24char",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "should return an error in case the provider is sing-box but options type is invalid",
			assert: func(t *testing.T, got []byte, err error) {
				assert.Error(t, err)
				assert.Nil(t, got)
			},
			givenArgs: args{
				ctx: ctx,
				cfg: &model.AnyConfig{
					Type:    model.ProviderSingBox,
					Options: "invalid-type",
				},
			},
		},
		{
			name: "should serialize a valid shadowsocks URL config successfully",
			assert: func(t *testing.T, got []byte, err error) {
				require.NoError(t, err)
				assert.JSONEq(t, expectedSSConfig, string(got))
			},
			givenArgs: args{
				ctx: ctx,
				cfg: &model.AnyConfig{
					Type:    model.ProviderURL,
					Options: []url.URL{ssURL},
				},
			},
		},
		{
			name: "should serialize a valid anytls URL config successfully",
			assert: func(t *testing.T, got []byte, err error) {
				require.NoError(t, err)
				assert.JSONEq(t, expectedAnyTLSConfig, string(got))
			},
			givenArgs: args{
				ctx: ctx,
				cfg: &model.AnyConfig{
					Type:    model.ProviderURL,
					Options: []url.URL{*anytlsURL},
				},
			},
		},
		{
			name: "should serialize a valid shadowsocks clash config successfully",
			assert: func(t *testing.T, got []byte, err error) {
				require.NoError(t, err)
				assert.JSONEq(t, expectedSSConfig, string(got))
			},
			givenArgs: args{
				ctx: ctx,
				cfg: &model.AnyConfig{
					Type:    model.ProviderClash,
					Options: []model.Outbound{ssOutbound},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes, err := p.Serialize(tt.givenArgs.ctx, tt.givenArgs.cfg)
			tt.assert(t, bytes, err)
		})
	}
}
