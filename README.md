# Goldfish Secrets

Browser-based, secure, single-use sharing of secrets. All cryptographic operations happen in the browser so the server never sees any plain-text secrets. Uses a server-local SQLite database or a remote Redis server to store browser-encrypted secrets.

Please run our pre-commit checks to format, lint, and test the code:
```
make precommit
```

Running locally in production mode, using embedded `app` assets:
```
make run
```

Running locally in development mode, using `app` assets directly from the filesystem:
```
make dev
```

Configuration options - [TOML](https://toml.io/en/) configuration file, environment variables, and command-line flags:
```
$> /app/goldfish -h
Usage: goldfish [flags]

Webapp for browser-based one-time secret management.

Flags:
  -h, --help           Show context-sensitive help.
  -c, --config=FILE    TOML configuration file.
  -v, --version        Show version and exit.

Application
  --addr="127.0.0.1:3000"           Server listen address ($LISTEN_ADDR).
  --pid-file="/app/goldfish.pid"    PID file path; use 'skip' to disable file creation ($PID_FILE).
  --breaker-ratio=0.1               Circuit-breaker failure ratio; use zero or less to disable the circuit-breaker ($BREAKER_RATIO).
  --backend="sqlite"                Backend to use for secret storage; either 'sqlite' or 'redis' ($BACKEND_STORE).

HTTPS listener
  --tls-cert=FILE    Server TLS certificate file path ($TLS_CERT_FILE).
  --tls-key=FILE     Server TLS private key file path ($TLS_KEY_FILE).

Rate-limiter
  --limit-count=1000            Maximum number of per-IP requests; use zero to disable the limiter ($RATE_LIMIT_COUNT).
  --limit-period=1h             Window of time for per-IP requests ($RATE_LIMIT_PERIOD).
  --limit-headers=header,...    Comma-separated list of HTTP request headers that can provide the remote IP address ($RATE_LIMIT_HEADERS).

SQLite backend
  --sqlite-file="/app/goldfish.db"    Database file path ($SQLITE_FILE).
  --sqlite-clean=1h                   Interval for removal of unaccessed expired secrets ($SQLITE_CLEAN).

Redis backend
  --redis-addr="localhost:6379"    Redis server address ($REDIS_ADDR).
  --redis-user=STRING              Redis username, if required ($REDIS_USER).
  --redis-pass=STRING              Redis password, if required ($REDIS_PASS).
  --redis-db=INT                   Redis db number, if required ($REDIS_DB).
  --redis-ns=STRING                Redis namespace, if required ($REDIS_NS).
  --redis-tls="off"                One of 'off', 'on', or 'insecure' ($REDIS_TLS).

Logging
  --log-level="info"        One of 'debug', 'info', 'warn', or 'error' ($LOG_LEVEL).
  --log-format="plain"      One of 'plain', 'text', or 'json' ($LOG_FORMAT).
  --log-access              Enable access logging; disabled by default ($LOG_ACCESS).
  --honey-api-key=STRING    Optional honeycomb.io key to their Events API ($HONEY_API_KEY).
  --honey-dataset=STRING    Optional honeycomb.io event dataset name ($HONEY_DATASET).
```
