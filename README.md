# ycauth

[Русская версия](./README.ru.md)

`ycauth` provides small Go modules for applications that use short-lived Yandex
Cloud IAM tokens. It includes token sources, a concurrency-safe cache,
ephemeral Object Storage credentials for AWS SDK v2, and IAM authentication for
new pgx v5 connections.

Use only the modules your application needs:

- `github.com/skarm/ycauth` — token sources and `Cache`.
- `github.com/skarm/ycauth/s3iam` — temporary Object Storage credentials for
  AWS SDK for Go v2.
- `github.com/skarm/ycauth/pgxiam` — IAM authentication for new pgx physical
  connections.

All modules require Go 1.25 or later. Add a released version of each required
module to `go.mod`:

```bash
go get github.com/skarm/ycauth@<version>
go get github.com/skarm/ycauth/s3iam@<version> # Object Storage only
go get github.com/skarm/ycauth/pgxiam@<version> # PostgreSQL only
```

## Architecture

```text
imds.Source or authzkey.Source
                │
                ▼
            ycauth.Cache ──── TokenProvider ──── s3iam or pgxiam
```

`TokenSource` obtains a fresh token. `Cache` turns it into a concurrent-safe
`TokenProvider` suitable for a request or connection hot path. `s3iam` and
`pgxiam` consume that provider; they do not store a long-lived IAM token.

Outbound requests send `User-Agent: ycauth` by default. Override it with
`imds.WithUserAgent`, `authzkey.WithUserAgent`, or
`s3iam.Config.UserAgent` when your application needs to identify itself.

## IAM token source and cache

Create one `Cache` for every independently configured identity and share it
between clients. It is safe for concurrent use.

### Compute Cloud VM: instance metadata

On a Compute Cloud VM with an attached service account, use `imds`. IMDS stands
for *instance metadata service*. It obtains the attached service account's IAM
token without an authorized-key file.

```go
source, err := imds.New()
if err != nil {
	return err
}

tokens, err := ycauth.NewCache(source, ycauth.CacheConfig{})
if err != nil {
	return err
}
```

The default metadata endpoint is link-local and intentionally uses HTTP. It is
only for a VM-local service; the default client disables proxies and redirects.
Outside Compute Cloud, that endpoint is normally unavailable.

### Other environments: authorized key

When instance metadata is unavailable, use a service-account authorized key:

```go
source, err := authzkey.NewFile("authorized-key.json")
if err != nil {
	return err
}

tokens, err := ycauth.NewCache(source, ycauth.CacheConfig{})
if err != nil {
	return err
}
```

`authzkey` validates the JSON document and RSA key, then exchanges a
short-lived signed JWT for an IAM token. It does not enforce file permissions:
secure storage and access control for the private key are the application's
responsibility.

Custom credential endpoints must use HTTPS. Plain HTTP is accepted only for
loopback, so local emulators and tests work without putting a credential on the
network; the metadata endpoint additionally accepts a link-local address, which
is where the instance metadata service answers. Credential clients, including
one you supply, have a finite timeout and do not follow redirects.

### Cache behavior

With `CacheConfig{}`, `Cache` starts a background refresh five minutes before
expiration, limits a refresh to ten seconds, and does not refresh a valid token
more than once every five seconds unless the token expires sooner than that.

- A cache hit reads an atomic snapshot and the clock once, taking no lock. The
  monotonic component schedules refreshes, while the wall clock enforces the
  token's absolute expiration.
- During the refresh window, callers immediately receive the current valid
  token while one shared refresh runs in the background.
- When the cache is empty or the token has expired, callers wait for that same
  shared refresh. Cancelling one caller cancels only its wait, never the shared
  refresh.
- On a refresh failure, the previous token may be returned only until its real
  expiration. Further attempts are throttled with exponential backoff.
- A panic from `TokenSource` becomes a refresh error rather than terminating
  the process.

Change `CacheConfig` only if the defaults do not fit the workload. Every zero
field keeps its default, including the fields of `BackoffConfig`:

```go
tokens, err := ycauth.NewCache(source, ycauth.CacheConfig{
	RefreshBefore: 2 * time.Minute,
	RefreshTimeout: 5 * time.Second,
	Backoff: ycauth.BackoffConfig{
		Initial:    time.Second,
		Max:        30 * time.Second,
		Multiplier: 2,
		Jitter:     0.2,
	},
})
```

`RefreshEvent` and `Observer` provide refresh telemetry without exposing token
contents. An observer must return promptly; observer panics are contained.

### Errors and invalidation

When backoff suppresses a new acquisition, distinguish it with `errors.Is`:

```go
token, err := tokens.Token(ctx)
if errors.Is(err, ycauth.ErrBackoff) {
	// A previous refresh failed; the next attempt is still throttled.
}
```

Call `tokens.Invalidate()` only when the IAM token itself is known to be
invalid. For example, after a new PostgreSQL connection fails because its IAM
credential is stale, invalidate and retry opening the connection. A wrong
database user, role, or endpoint will not be fixed by minting another token.

`*ycauth.APIError` includes an HTTP status code, request ID, bounded response
body excerpt, and any `Retry-After` hint. The hint is honoured as sent but
bounded to a few minutes, so one response cannot suspend refreshes for as long
as the server likes. The body is untrusted and can be sensitive, so avoid
logging it indiscriminately.

## Object Storage with AWS SDK v2

`s3iam.New` requests ephemeral AWS-compatible credentials and returns an
`*aws.CredentialsCache`. Assign it directly to `aws.Config`:

```go
policy, err := s3iam.PrefixPolicy(
	"my-bucket",
	"tenant/42",
	s3iam.PermissionReadObject |
		s3iam.PermissionListObjects |
		s3iam.PermissionWriteObject |
		s3iam.PermissionMultipartUpload,
)
if err != nil {
	return err
}

credentials, err := s3iam.New(tokens, s3iam.Config{
	SessionName:   "orders-api",
	Duration:      time.Hour,
	SessionPolicy: policy,
})
if err != nil {
	return err
}

awsConfig.Credentials = credentials
```

Only `SessionName` is required. `SessionPolicy` is optional; when omitted, the
ephemeral credentials can use every Object Storage permission already granted
to the subject. `Duration` must be a whole number of seconds from 15 minutes
through 12 hours; zero selects one hour. `RefreshTimeout` limits the whole
refresh, including IAM-token lookup, and defaults to ten seconds.

The AWS cache refreshes early. Yandex Cloud may cap an ephemeral key by the
remaining IAM-token lifetime, so `s3iam` clamps its early-refresh window to the
actual credentials lifetime. It never treats the adjusted AWS-cache expiration
as the real key expiration.

### Least-privilege policy

`PrefixPolicy` builds a compact inline policy for one bucket and object prefix.
The bucket name is validated against Object Storage naming rules. The prefix is
used exactly as supplied: it must not begin or end with `/`, and it may not
contain policy metacharacters (`*`, `?`, `$`) or control characters.

- `PermissionReadObject` permits downloads.
- `PermissionListObjects` permits listing under the selected prefix.
- `PermissionWriteObject` permits uploads.
- `PermissionDeleteObject` permits deletion.
- `PermissionMultipartUpload` permits multipart operations on selected objects,
  and implies the same `s3:PutObject` grant as `PermissionWriteObject`.
- `PermissionBucketLocation` permits reading the bucket location.

An empty prefix deliberately covers the whole bucket, so pass one only when that
is intended: an unset variable widens the policy instead of failing.

`PermissionMultipartUpload` does not grant `s3:ListBucketMultipartUploads`,
because that operation lists uploads for the entire bucket. Use `RawPolicy`
only when a typed policy cannot express the needed permission. It validates JSON
syntax and compacts the document, but cannot prove that an arbitrary policy is
safe. The compact document must fit Yandex Cloud's 2048-character inline-policy
limit.

### Refresh rejected S3 credentials

When Object Storage returns `ExpiredToken`, `InvalidToken`, or
`TokenRefreshRequired`, invalidate the AWS credentials cache, not the IAM token
cache:

```go
credentials.Invalidate()
```

Those errors use HTTP 400. Invalid access keys, security data, or request
signatures can use HTTP 403. See Yandex Cloud's [Object Storage response-code
reference](https://yandex.cloud/en/docs/storage/s3/api-ref/response-codes).

## Preparing a service account for PostgreSQL

Configure the service account and cluster before using `pgxiam`:

- Use the service account ID, such as `aje...`, as the PostgreSQL username. A
  service account name such as `my-service-account` is not a valid DSN username
  for this authentication flow.
- The IAM token must belong to the same service account whose ID is used as the
  username. Supply a `TokenProvider` that obtains it from the runtime context or
  metadata. On a Compute Cloud VM, use `imds`; where metadata is unavailable,
  use an authorized key with `authzkey`.
- Grant the connecting service account `iam.serviceAccounts.user` on that same
  service account as a resource, or on its containing folder. Odyssey needs the
  permission to read the account information. A broader role such as the
  primitive `auditor` role also works, but prefer `iam.serviceAccounts.user` for
  least privilege.
- Separately grant the service account the
  `managed-postgresql.clusters.connector` role on the target cluster. Create a
  database user whose name is the service account ID, whose authentication
  method is IAM, and which has access to the required database. `pgxiam` does
  not create these resources.

Grant the minimum role directly on the service account:

```bash
yc iam service-account add-access-binding <service-account-id> \
  --role iam.serviceAccounts.user \
  --subject serviceAccount:<service-account-id>
```

Alternatively, grant it on the folder from which the service account inherits
permissions:

```bash
yc resource-manager folder add-access-binding <folder-id> \
  --role iam.serviceAccounts.user \
  --subject serviceAccount:<service-account-id>
```

Configure cluster access and the database user with:

```bash
yc managed-postgresql cluster add-access-binding \
  --id <cluster-id> \
  --role managed-postgresql.clusters.connector \
  --service-account-id <service-account-id>

yc managed-postgresql user create <service-account-id> \
  --cluster-id <cluster-id> \
  --auth-method auth-method-iam \
  --permissions <database-name>
```

Verify that the ID in the DSN, the subject of these bindings, and the owner of
the IAM token are the same service account. See the Yandex Cloud documentation
for [service account access bindings](https://yandex.cloud/en/docs/iam/operations/sa/set-access-bindings),
[assigning roles](https://yandex.cloud/en/docs/iam/operations/roles/grant), and
[connecting to PostgreSQL with IAM](https://yandex.cloud/en/docs/managed-postgresql/operations/connect/clients).

## PostgreSQL with pgxpool

The IAM token travels as the connection password. The DSN username must be the
service account ID, such as `aje...`, not the service account name. The DSN must
also establish TLS: use `sslmode=verify-full` with the Yandex Cloud CA. pgx's
default of `sslmode=prefer` falls back to an unencrypted connection, and
`pgxiam` cannot detect that fallback—it configures connections, it does not
negotiate them.

Configure IAM authentication before opening the pool:

```go
poolConfig, err := pgxpool.ParseConfig(databaseURL)
if err != nil {
	return err
}

if authMode == "iam" {
	pgxiam.ConfigurePool(poolConfig, tokens)
}

pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
if err != nil {
	return err
}
defer pool.Close()

if err := pool.Ping(ctx); err != nil {
	return err
}
```

`ConfigurePool` preserves any existing `BeforeConnect` hook and runs it first.
It injects the IAM token into pgx's connection-local config copy immediately
before each physical connection, so the base pool config does not retain it.
Do not keep a static password in an IAM-auth DSN: IAM injection runs last and
replaces it.

Existing authenticated connections do not need to be closed merely because the
IAM token later expires. The token is required when a new physical connection
is created, not for every query.

## PostgreSQL with database/sql

Use pgx's stdlib connector rather than `sql.Open("pgx", dsn)`, which has a
static DSN and cannot rotate an IAM token:

```go
connectionConfig, err := pgx.ParseConfig(databaseURL)
if err != nil {
	return err
}

db := stdlib.OpenDB(*connectionConfig, pgxiam.StdlibOption(tokens))
defer db.Close()

db.SetMaxOpenConns(20)
db.SetMaxIdleConns(10)
db.SetConnMaxLifetime(time.Hour)

if err := db.PingContext(ctx); err != nil {
	return err
}
```

The endpoint must be configured for IAM authentication. This library does not
create cloud resources or discover database endpoints.

## Security and operations

- Treat IAM tokens, private keys, access keys, secret keys, and session tokens
  as secrets. `Token` redacts its value from JSON, `%s`, `%#v`, and `slog`, but
  direct access to `Token.Value` is still sensitive.
- HTTP responses, key files, and policy documents are validated. A nil token
  source or provider is rejected where it is supplied: constructors return an
  error, and the `pgxiam` hook builders panic. A nil context is a programmer
  error.
- Prefer `imds` on Compute Cloud. It avoids distributing a service-account
  private key to the workload.
- Keep one `Cache` and one AWS credentials cache per identity/configuration;
  creating them per request defeats refresh coalescing.

## Development and releases

The modules are versioned independently. `go.work` is deliberately ignored, so
CI tests each module outside a workspace.

```bash
go test -race ./...
go vet ./...
golangci-lint run ./...
```

When a root-module API changes for `s3iam` or `pgxiam`, add a local, uncommitted
`replace github.com/skarm/ycauth => ..` directive in that submodule.
Release the root module first, update the submodule requirement to the released
version, then run `go mod tidy -diff`, `go build ./...`, `go vet ./...`, and
`go test -race ./...` with `GOWORK=off` and no replace directive before tagging
the submodule.

## Security reporting

Report vulnerabilities privately through this repository's GitHub Security
Advisories rather than a public issue.

## License

[MIT](./LICENSE).
