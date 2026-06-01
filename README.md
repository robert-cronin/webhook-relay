# webhook-relay

A small high-throughput HTTP webhook forwarder. Receives signed webhooks on
configured paths, validates JWT bearer tokens, and forwards to downstream
destinations defined in a YAML config.

This Go binary is paired with a Python sidecar that handles payload
templating (Jinja2) and at-rest encryption (cryptography).

## Build

```
go build ./...
```
