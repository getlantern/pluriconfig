# pluriconfig

This project intends to deal with different proxy configuration standards and 
provide a unified way to parse them into a common format or convert between them.

## Supported Formats Examples

### URL standard

This the list of supported protocols and their URL formats:

- `vmess://<base64_encoded_json_config>` (see the expected JSON config below)
- `vless://<uuid>@host:port[?<v2rayParams>][<tlsParams>]#name` (see the optional v2ray and tls params below)
- `trojan://<password>@host:port[?[<v2rayParams>][<tlsParams>]]#name`
- `ss://[<base64_encoded(encryption_method:password)>][password]@host:port#name`

Some optional v2ray parameters (for vmess, vless, and trojan):

- `type`: connection type, can be `http`, `httpupgrade` or `xhttp`, `ws` or `wss`, `grpc`, or `quic`
- `host`: the host header for ws/wss/http/httpupgrade
- `path`: the path for ws/wss/http/httpupgrade
- `serviceName`: the service name for grpc
- `method`: for http 

Some optional tls parameters (for vmess, vless, and trojan):

- `security`: can be `tls` or `none`
- `sni`: the sni value for tls
- `alpn`: the alpn value for tls, can be `h2` or `http/1.1`
- `allowInsecure`: can be `1` or `0`, indicates whether to allow insecure tls

vmess decoded config example

```json
{
  "add": "example.com",
  "port": 443,
  "aid": 0,
  "alpn": "h2",
  "host": "example.com",
  "id": "uuid-string-here",
  "net": "ws",
  "path": "/websocket",
  "scy": "auto",
  "sni": "example.com",
  "tls": "tls"
}
```

### Sing-box JSON config

```json
{
  "tag": "name",
  "type": "shadowsocks",
  "method": "encryption_method",
  "password": "password",
}
```

## Usage
Go get the package:
```bash
go get -u github.com/getlantern/pluriconfig
```

Import and use it in your Go code:
```go
import (
    "github.com/getlantern/pluriconfig"
    _ "github.com/getlantern/pluriconfig/provider/singbox"
)

...

provider, _ := pluriconfig.GetProvider("singbox")
config, _ := provider.Parse(ctx, "vmess://base64_encoded_string")
```
