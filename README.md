# Volcano Cert Sync

`volcano-cert-sync` is a small, one-shot Go program that reconciles one
Kubernetes `kubernetes.io/tls` Secret to explicitly named Volcengine
acceleration domains. Kubernetes schedules it as a CronJob; the program does
not run a daemon and does not delete old cloud certificates.

It exists to make certificate rotation observable and safe across three
separate product APIs:

- **DCDN** — imports/reuses the certificate in Certificate Center and binds it
  to all mismatched DCDN domains in one provider request.
- **MCDN** — reads MCDN state through the official SDK and requires an
  account-reviewed request template before it can submit the otherwise
  undocumented certificate-deployment action.
- **CDN** — retains explicit standard-CDN support for legacy targets only.

## Safety model

Before a real run performs any write, it:

1. reads and cryptographically validates the source TLS Secret;
2. proves the private key matches the leaf certificate and that the certificate
   is currently valid;
3. verifies each configured domain is covered by the certificate SANs;
4. reads the provider-side certificate binding and makes a verified public TLS
   connection to every target;
5. compares SHA-256 leaf-certificate fingerprints; and only then
6. preflights and submits the minimum required provider update, then waits for
   both provider and public TLS fingerprints to converge.

`--dry-run` still executes steps 1–5. It does **not** import, bind, or deploy a
certificate. Product types are explicit; an unknown type is rejected instead
of silently falling back to CDN.

The program emits structured JSON logs containing only target names, actions,
short fingerprints, and safe errors. It never logs PEM data, private keys,
AccessKey values, SecretKey values, or cloud request bodies.

## Configuration

Copy the sanitized example locally; do not commit the resulting `.env` file.

```bash
cp .env.example .env
chmod 600 .env
```

| Variable | Required | Description |
| --- | --- | --- |
| `VOLCENGINE_ACCESS_KEY` | Yes | Least-privilege Volcengine service identity access key. |
| `VOLCENGINE_SECRET_KEY` | Yes | Matching secret key. Keep it in an encrypted Kubernetes Secret for production. |
| `K8S_SECRET_NAME` | Yes | Source Secret name. It must be type `kubernetes.io/tls`. |
| `K8S_SECRET_NAMESPACE` | Yes | Source Secret namespace. |
| `SYNC_TARGETS` | Yes | Comma-separated `domain:type` entries. Types are `cdn`, `dcdn`, and `mcdn`. |
| `DRY_RUN` | No | `true` makes a full, read-only reconciliation run. |
| `MCDN_DEPLOY_REQUEST_TEMPLATE` | Live MCDN only | Account-reviewed JSON for `SubmitCertificateDeployTask`; see [MCDN gate](#mcdn-deployment-gate). |

For example:

```dotenv
K8S_SECRET_NAME=source-tls-secret
K8S_SECRET_NAMESPACE=example-namespace
SYNC_TARGETS=api.example.com:dcdn,media.example.com:mcdn
```

The old `CDN_DOMAINS` variable is supported only for a legacy standard-CDN
configuration. New configuration should always use `SYNC_TARGETS` with an
explicit type.

## Local usage

Install the pinned Go toolchain with [mise](https://mise.jdx.dev/) or use Go
1.26.7 directly.

```bash
mise install
go mod download
go test ./...
go run ./cmd/sync --dry-run
```

Outside a cluster, Kubernetes client-go uses `KUBECONFIG` when set, otherwise
your normal `~/.kube/config`. In a cluster it uses the projected ServiceAccount
token and cluster CA. TLS verification is never disabled.

For an intentional write after reviewing the dry-run output:

```bash
go run ./cmd/sync
```

## MCDN deployment gate

The public MCDN SDK exposes state inspection but does not publish the exact
payload schema for the privileged `SubmitCertificateDeployTask` action. This
repository intentionally refuses a mutating MCDN run without an authorized
template instead of guessing a write payload.

Obtain the request shape from the authorized Volcengine console/API owner,
review it, and store it only in encrypted private GitOps configuration. The
template may use these placeholders:

| Placeholder | Runtime value |
| --- | --- |
| `{{CERTIFICATE_ID}}` | Imported/reused Certificate Center instance ID. |
| `{{RESOURCE_ID}}` | Exact MCDN resource ID obtained by a read-only lookup. |
| `{{CLOUD_ACCOUNT_ID}}` | MCDN cloud-account ID obtained by a read-only lookup. |
| `{{DOMAIN}}` | Configured domain. |
| `{{VENDOR}}` | Provider-reported vendor. |
| `{{SUB_PRODUCT}}` | Provider-reported sub-product. |

The program verifies the target is the expected built-in CDN MCDN resource
before submitting. It validates every rendered JSON payload before importing a
private key into Certificate Center.

## Container and Kubernetes deployment

Build a local image:

```bash
docker build --build-arg VERSION=dev -t volcano-cert-sync:dev .
docker run --rm volcano-cert-sync:dev --version
```

The image is built as `linux/amd64`, contains only the statically linked binary
and CA certificates, and runs as UID/GID 65532. `.dockerignore` excludes
credentials, local kubeconfigs, Git metadata, source releases, and deployment
configuration.

Generic, non-production manifests live in [deploy/](deploy/README.md). They
demonstrate:

- a six-hour CronJob with `concurrencyPolicy: Forbid`, a 15-minute deadline,
  no automatic retry, and bounded history;
- a role that can only `get` the single named source TLS Secret;
- non-root, read-only filesystem, dropped capabilities, seccomp, and bounded
  resources; and
- an immutable image digest and encrypted-cloud-credential boundary.

Use a separate private GitOps repository for real namespaces, source secret
names, image digests, and encrypted credentials. A useful production split is
one CronJob in each source Secret namespace; it avoids cross-namespace Secret
read permissions and reuses namespace-local registry pull credentials.

## Release and image promotion

Pushing a signed version tag, for example `v1.0.0`, triggers the release
workflow. It builds an immutable `linux/amd64` image in private GHCR, generates
an SBOM, publishes provenance, and keylessly signs the digest with Cosign. It
does not publish a mutable `latest` tag.

Promote that exact digest from a controlled host to the existing Volcengine
Container Registry namespace, then pin the Volcengine registry digest in GitOps
and test a suspended/manual Kubernetes Job before enabling the CronJobs. Log
out from GHCR on the promotion host after the transfer. Do not copy image pull
credentials or cloud access credentials into this source repository.

## CI, security, and dependency policy

GitHub Actions runs on pull requests and `main` pushes:

- `gofmt`, `go mod tidy` diff check, module verification, `go vet`, race tests,
  staticcheck, and `govulncheck`;
- reproducible container build and HIGH/CRITICAL Trivy image scan;
- full-history Gitleaks scanning and workflow linting;
- CodeQL on pushes, pull requests, and a weekly schedule; and
- tag-only GHCR build, SBOM, provenance, and Cosign signing.

Dependabot opens weekly Go module and GitHub Actions updates. Action references
are pinned to commit SHAs. The primary runtime dependencies are Go 1.26.7,
Volcengine SDK 1.2.50, and Kubernetes client-go 0.33.13; all Kubernetes modules
are kept on the same 0.33.13 release line to avoid schema incompatibilities.

Run the relevant checks locally:

```bash
gofmt -w cmd internal
go test -race ./...
go vet ./...
go mod verify
```

## Repository layout

```text
cmd/sync/                 CLI entrypoint and structured logging
internal/cert/            PEM, key-pair, validity, SAN, and fingerprint checks
internal/config/          explicit environment parsing and validation
internal/k8s/             in-cluster/kubeconfig TLS Secret reader
internal/syncer/          product-neutral read/plan/deploy/verify reconciler
internal/volcengine/      DCDN, MCDN, CDN, and Certificate Center adapters
deploy/example/           sanitized least-privilege Kubernetes example
.github/workflows/        CI, security analysis, and release pipeline
```

## License

[MIT](LICENSE) © 2026 Berny Linville
