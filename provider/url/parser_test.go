package url

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/getlantern/pluriconfig/model"
	"github.com/sagernet/sing-box/option"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser_Parse(t *testing.T) {
	p := parser{}
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		wantURLs []string
		wantErr  bool
	}{
		{
			name:     "single valid URL",
			input:    "http://example.com:8080",
			wantURLs: []string{"http://example.com:8080"},
		},
		{
			name:     "multiple URLs separated by newline",
			input:    "http://a.com:1\nhttp://b.com:2",
			wantURLs: []string{"http://a.com:1", "http://b.com:2"},
		},
		{
			name:     "multiple URLs separated by comma and spaces",
			input:    "http://a.com:1, http://b.com:2",
			wantURLs: []string{"http://a.com:1", "http://b.com:2"},
		},
		{
			name:     "empty input",
			input:    "",
			wantURLs: []string{},
		},
		{
			name:    "invalid URL",
			input:   "://bad-url",
			wantErr: true,
		},
		{
			name:     "input with extra whitespace",
			input:    "   http://a.com:1   \n\t,http://b.com:2  ",
			wantURLs: []string{"http://a.com:1", "http://b.com:2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := p.Parse(ctx, []byte(tt.input))
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, model.ProviderURL, cfg.Type)
			urls, ok := cfg.Options.([]url.URL)
			require.True(t, ok)
			require.Len(t, urls, len(tt.wantURLs))
			for i, want := range tt.wantURLs {
				assert.Equal(t, want, urls[i].String())
			}
		})
	}
}

func TestParser_Serialize(t *testing.T) {
	p := parser{}
	ctx := context.Background()

	tests := []struct {
		name   string
		config *model.AnyConfig
		assert func(t *testing.T, out []byte, err error)
	}{
		{
			name: "ProviderURL with multiple URLs",
			config: &model.AnyConfig{
				Type: model.ProviderURL,
				Options: []url.URL{
					{Scheme: "http", Host: "a.com:1"},
					{Scheme: "https", Host: "b.com:2"},
				},
			},
			assert: func(t *testing.T, out []byte, err error) {
				require.NoError(t, err)
				outStr := string(out)
				assert.Contains(t, outStr, "http://a.com:1")
				assert.Contains(t, outStr, "https://b.com:2")
			},
		},
		{
			name: "ProviderURL with empty URLs",
			config: &model.AnyConfig{
				Type:    model.ProviderURL,
				Options: []url.URL{},
			},
			assert: func(t *testing.T, out []byte, err error) {
				require.NoError(t, err)
				outStr := string(out)
				assert.True(t, outStr == "" || outStr == "\n")
			},
		},
		{
			name: "ProviderSingBox Shadowsocks edge case",
			config: &model.AnyConfig{
				Type: model.ProviderSingBox,
				Options: model.SingBoxOptions{
					Outbounds: []option.Outbound{
						{
							Type: "shadowsocks",
							Options: option.ShadowsocksOutboundOptions{
								Method: "none",
								ServerOptions: option.ServerOptions{
									Server:     "host",
									ServerPort: 123,
								},
								Password: "",
							},
							Tag: "tag",
						},
					},
				},
			},
			assert: func(t *testing.T, out []byte, err error) {
				require.NoError(t, err)
				outStr := string(out)
				assert.Contains(t, outStr, "ss://host:123#tag")
			},
		},
		{
			name: "ProviderSingBox Trojan edge case",
			config: &model.AnyConfig{
				Type: model.ProviderSingBox,
				Options: model.SingBoxOptions{
					Outbounds: []option.Outbound{
						{
							Type: "trojan",
							Options: option.TrojanOutboundOptions{
								ServerOptions: option.ServerOptions{
									Server:     "trojanhost",
									ServerPort: 443,
								},
								Password: "pass",
								OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
									TLS: &option.OutboundTLSOptions{
										ServerName: "sni",
										ALPN:       []string{"h2"},
										Insecure:   true,
									},
								},
								Transport: &option.V2RayTransportOptions{Type: "ws", WebsocketOptions: option.V2RayWebsocketOptions{Path: "/ws"}},
							},
							Tag: "trojantag",
						},
					},
				},
			},
			assert: func(t *testing.T, out []byte, err error) {
				require.NoError(t, err)
				outStr := string(out)
				assert.Contains(t, outStr, "trojan://")
				assert.Contains(t, outStr, "trojanhost:443")
				assert.Contains(t, outStr, "sni=sni")
				assert.Contains(t, outStr, "alpn=h2")
				assert.Contains(t, outStr, "allowInsecure=true")
				assert.Contains(t, outStr, "type=ws")
				assert.Contains(t, outStr, "path=%2Fws")
				assert.Contains(t, outStr, "#trojantag")
			},
		},
		{
			name: "ProviderSingBox Vmess encoding",
			config: &model.AnyConfig{
				Type: model.ProviderSingBox,
				Options: model.SingBoxOptions{
					Outbounds: []option.Outbound{
						{
							Type: "vmess",
							Options: option.VMessOutboundOptions{
								ServerOptions: option.ServerOptions{
									Server:     "vmesshost",
									ServerPort: 1000,
								},
								UUID:     "uuid",
								Security: "auto",
								AlterId:  0,
								OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
									TLS: &option.OutboundTLSOptions{
										Enabled:    true,
										ServerName: "sni",
										ALPN:       []string{"h2"},
									},
								},
								Transport: &option.V2RayTransportOptions{
									Type:             "ws",
									WebsocketOptions: option.V2RayWebsocketOptions{Path: "/ws"},
								},
							},
						},
					},
				},
			},
			assert: func(t *testing.T, out []byte, err error) {
				require.NoError(t, err)
				outStr := string(out)
				assert.Contains(t, outStr, "vmess://")
				u, err := url.Parse(strings.TrimSpace(outStr))
				require.NoError(t, err)
				decoded, err := base64.StdEncoding.DecodeString(u.Host)
				require.NoError(t, err, u)
				var cfg model.VMESSConfig
				require.NoError(t, json.Unmarshal(decoded, &cfg), "couldn't unmarshal vmess config: %+v", u)
				assert.Equal(t, "vmesshost", cfg.Addr)
				assert.Equal(t, uint16(1000), cfg.Port)
				assert.Equal(t, "uuid", cfg.ID)
				assert.Equal(t, "tls", cfg.TLS)
				assert.Equal(t, "ws", cfg.Net)
				assert.Equal(t, "/ws", cfg.Path)
			},
		},
		{
			name: "Unsupported config type",
			config: &model.AnyConfig{
				Type:    "unknown",
				Options: nil,
			},
			assert: func(t *testing.T, out []byte, err error) {
				assert.Error(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := p.Serialize(ctx, tt.config)
			tt.assert(t, out, err)
		})
	}
}

func TestParseSerialize(t *testing.T) {
	p := parser{}
	ctx := context.Background()

	originalInput := "http://example.com:8080\nhttps://another.com:443"
	cfg, err := p.Parse(ctx, []byte(originalInput))
	require.NoError(t, err)
	urls, ok := cfg.Options.([]url.URL)
	require.True(t, ok)
	assert.Equal(t, urls[0], url.URL{Scheme: "http", Host: "example.com:8080"})
	assert.Equal(t, urls[1], url.URL{Scheme: "https", Host: "another.com:443"})

	serializedOutput, err := p.Serialize(ctx, cfg)
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSpace(originalInput), strings.TrimSpace(string(serializedOutput)))
}
