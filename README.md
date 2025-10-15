# Ratio1 Plugins Sandbox

The Ratio1 Plugins Sandbox is a self-contained HTTP server that mimics the CStore and R1FS FastAPI plugins used by Ratio1 edge nodes. It keeps the official mocks behind HTTP endpoints so that SDK clients and other integrations can be exercised locally without a live infrastructure.

It is designed to run alongside [ratio1_sdk_go](https://github.com/Ratio1/ratio1_sdk_go) and [edge-node-client](https://github.com/Ratio1/edge-node-client) during product development, so you can validate end-to-end flows without connecting to a live node.

## Release artifacts

Every push to `main` triggers the release workflow in `.github/workflows/release.yml`. It builds cross-platform archives and publishes them to the [latest release](https://github.com/Ratio1/r1-plugins-sandbox/releases/latest).

| OS      | Arch  | Archive                                  | Download                                                                                                                 |
| ------- | ----- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Linux   | amd64 | `r1-plugins-sandbox_linux_amd64.tar.gz`  | [Download](https://github.com/Ratio1/r1-plugins-sandbox/releases/latest/download/r1-plugins-sandbox_linux_amd64.tar.gz)  |
| Linux   | arm64 | `r1-plugins-sandbox_linux_arm64.tar.gz`  | [Download](https://github.com/Ratio1/r1-plugins-sandbox/releases/latest/download/r1-plugins-sandbox_linux_arm64.tar.gz)  |
| macOS   | amd64 | `r1-plugins-sandbox_darwin_amd64.tar.gz` | [Download](https://github.com/Ratio1/r1-plugins-sandbox/releases/latest/download/r1-plugins-sandbox_darwin_amd64.tar.gz) |
| macOS   | arm64 | `r1-plugins-sandbox_darwin_arm64.tar.gz` | [Download](https://github.com/Ratio1/r1-plugins-sandbox/releases/latest/download/r1-plugins-sandbox_darwin_arm64.tar.gz) |
| Windows | amd64 | `r1-plugins-sandbox_windows_amd64.zip`   | [Download](https://github.com/Ratio1/r1-plugins-sandbox/releases/latest/download/r1-plugins-sandbox_windows_amd64.zip)   |

Extract the archive, place `r1-plugins-sandbox` (or `r1-plugins-sandbox.exe`) on your `PATH`, and you are ready to go.
If macOS warns that the binary is from an unidentified developer, follow Apple's steps to [open the app anyway](https://support.apple.com/HT202491).

## Highlights

-   Ships the same REST surface as the production plugins (`/set`, `/get`, `/add_file`, `/get_status`, and more).
-   Emits ready-to-copy environment exports so existing clients can discover the sandbox automatically.
-   Provides deterministic seeding, latency injection, and fault simulation for integration tests.
-   Produces detailed request/response logs to help debug your flows.

## Download a release build

Grab the artifact that matches your platform from the table above or directly from the [releases page](https://github.com/Ratio1/r1-plugins-sandbox/releases/latest), then make it executable and run it.

```bash
# macOS arm64 example
curl -L https://github.com/Ratio1/r1-plugins-sandbox/releases/latest/download/r1-plugins-sandbox_darwin_arm64.tar.gz \
  | tar -xz
chmod +x r1-plugins-sandbox
./r1-plugins-sandbox --help
```

Windows users can download `r1-plugins-sandbox_windows_amd64.zip`, unzip it, and run `r1-plugins-sandbox.exe`.

## Run the sandbox

```bash
./r1-plugins-sandbox --cstore-addr :8787 --r1fs-addr :8788
```

When the server starts it prints the environment variables you need to export:

```
export R1_RUNTIME_MODE=http
export EE_CHAINSTORE_API_URL=http://127.0.0.1:8787
export EE_R1FS_API_URL=http://127.0.0.1:8788
```

Paste those into your shell (or pipe them into a file and `source` it) before launching your client. The sandbox keeps running until you stop it with `Ctrl+C`.

### CLI flags

| Flag            | Default | Description                                                                             |
| --------------- | ------- | --------------------------------------------------------------------------------------- |
| `--cstore-addr` | `:8787` | Listen address for the CStore mock.                                                     |
| `--r1fs-addr`   | `:8788` | Listen address for the R1FS mock.                                                       |
| `--kv-seed`     |         | Path to a JSON file with initial CStore entries.                                        |
| `--fs-seed`     |         | Path to a JSON file with initial R1FS files.                                            |
| `--latency`     | `0`     | Adds fixed delay (e.g. `200ms`) to every request.                                       |
| `--fail`        |         | Failure injection string `rate=<float>,code=<status>`; omit `code` to default to `500`. |

Combine flags as needed, for example:

```bash
./r1-plugins-sandbox \
  --kv-seed seeds/cstore.json \
  --fs-seed seeds/r1fs.json \
  --latency 150ms \
  --fail rate=0.03,code=429
```

### Seeding data

Seed files let you start the sandbox with predictable state. Both seeds are JSON arrays:

```json
[
	{
		"key": "jobs:123",
		"value": { "status": "queued" }
	}
]
```

```json
[
	{
		"path": "/artifacts/report.json",
		"base64": "eyJvayI6IHRydWV9",
		"content_type": "application/json",
		"metadata": { "workflow": "ci" }
	}
]
```

-   CStore seeds accept `key`, raw JSON `value`.
-   R1FS seeds expect the file `path`, base64-encoded content, optional `content_type`, `metadata`, and `last_modified`.

The helpers in `internal/devseed` handle decoding and validation before seeding the in-memory stores.

### Failure injection and latency

Use `--latency` to simulate slow dependencies and `--fail` to trigger intermittent errors. For example, `--fail rate=0.1,code=503` makes roughly 10% of requests return a `503 Service Unavailable` response. These knobs are useful when validating client retries and timeout handling.

## HTTP surface

**CStore**

-   `POST /set` – store a value.
-   `GET /get` – fetch a value by key.
-   `POST /hset` / `GET /hget` / `GET /hgetall` – hash primitives.
-   `GET /get_status` – inspect current keys.

**R1FS**

-   `POST /add_file`, `POST /add_file_base64` – upload binary or base64 data.
-   `GET /get_file`, `GET /get_file_base64` – download stored content.
-   `POST /add_yaml`, `POST /add_json`, `POST /add_pickle` – structured helpers.
-   `POST /calculate_json_cid`, `POST /calculate_pickle_cid` – deterministic CID generation without storing.
-   `GET /get_yaml` – retrieve YAML payloads.
-   `GET /get_status` – list known files.

All handlers log request and response bodies along with duration to make debugging straightforward.

## Build from source

You only need Go 1.21+:

```bash
go build -o r1-plugins-sandbox
./r1-plugins-sandbox --help
```

Or run without building:

```bash
go run .
```

Run `go test ./...` to execute unit tests for the mocks and server helpers.

## Contributing

Issues and pull requests are welcome. Please open an issue if you spot regressions in the HTTP surface, need extra fixtures, or want to extend the failure injection options.
