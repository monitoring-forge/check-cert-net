# check-cert-net

`check-cert-net` is a [Mackerel](https://mackerel.io/) check plugin that monitors the expiration date of a remote TLS certificate using OpenSSL `s_client`.

## Features

- Check TLS certificate expiry via `openssl s_client`.
- Customizable warning and critical thresholds in days.
- Support for SNI (`--servername`) and hostname verification (`--verify-servername`).
- Option to prefer RSA or ECDSA cipher suites.
- IPv6 host support.

## Requirements

- OpenSSL installed on the execution host
- Go 1.25 or later (to build from source)

## Installation via mkr plugin

```sh
mkr plugin install monitoring-forge/check-cert-net
```

## Usage

```sh
./check-cert-net -h
```

```
Usage:
  check-cert-net [OPTIONS]

Application Options:
  -H, --host=              Hostname (default: localhost)
  -p, --port=              Port (default: 443)
      --servername=        servername in ClientHello
      --verify-servername  verify servername
      --timeout=           Timeout to connect to server (default: 5s)
      --rsa                Preferred aRSA cipher to use
      --ecdsa              Preferred aECDSA cipher to use
  -c, --critical=          The critical threshold in days before expiry (default: 14)
  -w, --warning=           The threshold in days before expiry (default: 30)
  -v, --version            Show version

Help Options:
  -h, --help               Show this help message
```

## Examples

### Basic check

```sh
check-cert-net --host example.com --port 443
```

### Check a specific virtual host with SNI

```sh
check-cert-net --host 127.0.0.1 --port 443 --servername example.com
```

### Verify the certificate matches the requested server name

```sh
check-cert-net --host example.com --servername example.com --verify-servername
```

### Use RSA cipher and custom thresholds

```sh
check-cert-net --servername example.com --host 127.0.0.1 --port 443 --rsa -w 10 -c 7
```

Example output:

```
check-cert-net OK: Expiration date: 2020-07-02, 62 days remaining
```

## Exit codes

| Code | Status  | Description                              |
|------|---------|------------------------------------------|
| 0    | OK      | Certificate is valid and not expiring soon. |
| 1    | WARNING | Certificate expires within warning days. |
| 2    | CRITICAL| Certificate expires within critical days or connection failed. |
| 3    | UNKNOWN | An unknown error occurred.               |


## License

See [LICENSE](LICENSE).

