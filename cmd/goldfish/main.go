package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	log "log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/honeycombio/libhoney-go"
	"github.com/tomcz/gotools/honeylogger"
	"github.com/tomcz/gotools/quiet"
	"github.com/tomcz/gotools/reloader"
	"github.com/tomcz/gotools/runner"
	altsrc "github.com/urfave/cli-altsrc/v3"
	"github.com/urfave/cli-altsrc/v3/toml"
	"github.com/urfave/cli/v3"
)

var (
	configFile string

	listenAddr   string
	pidFilePath  string
	breakerRatio float64

	tlsCertFile string
	tlsKeyFile  string

	limitCount   uint64
	limitPeriod  time.Duration
	limitHeaders string

	storeType        string
	storeSqliteFile  string
	storeSqliteClean time.Duration
	storeRedisAddr   string
	storeRedisUser   string
	storeRedisPass   string
	storeRedisDB     int
	storeRedisNS     string
	storeRedisTLS    string

	logLevel     string
	logFormat    string
	logAccess    bool
	honeyApiKey  string
	honeyDataset string

	showShutdown  bool
	closeLibhoney bool

	version string // set by build
)

const (
	gracefulTimeout  = 100 * time.Millisecond
	skipPidFile      = "skip"
	sqliteStoreType  = "sqlite"
	redisStoreType   = "redis"
	redisTlsOn       = "on"
	redisTlsOff      = "off"
	redisTlsInsecure = "insecure"
)

func configFileOrEnvVar(fileKey, envKey string) cli.ValueSourceChain {
	return cli.NewValueSourceChain(toml.TOML(fileKey, altsrc.NewStringPtrSourcer(&configFile)), cli.EnvVar(envKey))
}

func main() {
	pname, err := os.Executable()
	if err != nil {
		log.Error("Unable to determine executable path", "err", err)
		os.Exit(1)
	}
	app := &cli.Command{
		Name:            "goldfish",
		Usage:           "Webapp for browser-based one-time secret management",
		ArgsUsage:       " ", // no positional arguments
		Before:          setupLogging,
		Action:          startService,
		Version:         version,
		HideHelpCommand: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Usage:       "TOML configuration `file`",
				Destination: &configFile,
			},
			&cli.StringFlag{
				Name:        "addr",
				Usage:       "Server listen address",
				Value:       "127.0.0.1:3000",
				Category:    "Application",
				Destination: &listenAddr,
				Sources:     configFileOrEnvVar("addr", "LISTEN_ADDR"),
			},
			&cli.StringFlag{
				Name:        "pid-file",
				Usage:       fmt.Sprintf("PID file `path`; use %q to disable file creation", skipPidFile),
				Value:       fmt.Sprintf("%s.pid", pname),
				Category:    "Application",
				Destination: &pidFilePath,
				Sources:     configFileOrEnvVar("pid-file", "PID_FILE"),
			},
			&cli.Float64Flag{
				Name:        "breaker-ratio",
				Usage:       "Circuit-breaker failure ratio; zero or less to disable the circuit-breaker",
				Value:       0.1,
				Category:    "Application",
				Destination: &breakerRatio,
				Sources:     configFileOrEnvVar("breaker-ratio", "BREAKER_RATIO"),
			},
			&cli.StringFlag{
				Name:        "backend",
				Usage:       fmt.Sprintf("Backend to use for secret `storage`, either %q or %q", sqliteStoreType, redisStoreType),
				Value:       sqliteStoreType,
				Category:    "Application",
				Destination: &storeType,
				Sources:     configFileOrEnvVar("backend", "BACKEND_STORE"),
			},
			&cli.StringFlag{
				Name:        "sqlite-file",
				Usage:       "Database file `path`",
				Value:       fmt.Sprintf("%s.db", pname),
				Category:    "SQLite backend",
				Destination: &storeSqliteFile,
				Sources:     configFileOrEnvVar("sqlite-file", "SQLITE_FILE"),
			},
			&cli.DurationFlag{
				Name:        "sqlite-clean",
				Usage:       "Interval for removal of unaccessed expired secrets",
				Value:       time.Hour,
				Category:    "SQLite backend",
				Destination: &storeSqliteClean,
				Sources:     configFileOrEnvVar("sqlite-clean", "SQLITE_CLEAN"),
			},
			&cli.StringFlag{
				Name:        "redis-addr",
				Usage:       "Redis address",
				Value:       "localhost:6379",
				Category:    "Redis backend",
				Destination: &storeRedisAddr,
				Sources:     configFileOrEnvVar("redis-addr", "REDIS_ADDR"),
			},
			&cli.StringFlag{
				Name:        "redis-user",
				Usage:       "Redis username, if required",
				Category:    "Redis backend",
				Destination: &storeRedisUser,
				Sources:     configFileOrEnvVar("redis-user", "REDIS_USER"),
			},
			&cli.StringFlag{
				Name:        "redis-pass",
				Usage:       "Redis password, if required",
				Category:    "Redis backend",
				Destination: &storeRedisPass,
				Sources:     configFileOrEnvVar("redis-pass", "REDIS_PASS"),
			},
			&cli.IntFlag{
				Name:        "redis-db",
				Usage:       "Redis db `number`, if required",
				Category:    "Redis backend",
				Destination: &storeRedisDB,
				Sources:     configFileOrEnvVar("redis-db", "REDIS_DB"),
			},
			&cli.StringFlag{
				Name:        "redis-ns",
				Usage:       "Redis namespace, if required",
				Category:    "Redis backend",
				Destination: &storeRedisNS,
				Sources:     configFileOrEnvVar("redis-ns", "REDIS_NS"),
			},
			&cli.StringFlag{
				Name:        "redis-tls",
				Usage:       fmt.Sprintf("Either %q, %q, or %q", redisTlsOff, redisTlsOn, redisTlsInsecure),
				Value:       redisTlsOff,
				Category:    "Redis backend",
				Destination: &storeRedisTLS,
				Sources:     configFileOrEnvVar("redis-tls", "REDIS_TLS"),
			},
			&cli.StringFlag{
				Name:        "tls-cert",
				Usage:       "Server TLS certificate `file` path",
				Category:    "HTTPS listener",
				Destination: &tlsCertFile,
				Sources:     configFileOrEnvVar("tls-cert", "TLS_CERT_FILE"),
			},
			&cli.StringFlag{
				Name:        "tls-key",
				Usage:       "Server TLS private key `file` path",
				Category:    "HTTPS listener",
				Destination: &tlsKeyFile,
				Sources:     configFileOrEnvVar("tls-key", "TLS_KEY_FILE"),
			},
			&cli.Uint64Flag{
				Name:        "limit-count",
				Usage:       "Maximum `number` of requests, per IP; zero to disable the limiter",
				Value:       1000,
				Category:    "Rate-limiter",
				Destination: &limitCount,
				Sources:     configFileOrEnvVar("limit-count", "RATE_LIMIT_COUNT"),
			},
			&cli.DurationFlag{
				Name:        "limit-period",
				Usage:       "Window of `time` for requests, per IP",
				Value:       time.Hour,
				Category:    "Rate-limiter",
				Destination: &limitPeriod,
				Sources:     configFileOrEnvVar("limit-period", "RATE_LIMIT_PERIOD"),
			},
			&cli.StringFlag{
				Name:        "limit-headers",
				Usage:       "Comma-separated `list` of http request headers that can provide an IP address",
				Category:    "Rate-limiter",
				Destination: &limitHeaders,
				Sources:     configFileOrEnvVar("limit-headers", "RATE_LIMIT_HEADERS"),
			},
			&cli.StringFlag{
				Name:        "log-level",
				Usage:       "Log `severity` level, one of \"debug\", \"info\", \"warn\", or \"error\"",
				Value:       "info",
				Category:    "Logging",
				Destination: &logLevel,
				Sources:     configFileOrEnvVar("log-level", "LOG_LEVEL"),
			},
			&cli.StringFlag{
				Name:        "log-format",
				Usage:       "Structured log format, one of \"plain\", \"text\", or \"json\"",
				Value:       "plain",
				Category:    "Logging",
				Destination: &logFormat,
				Sources:     configFileOrEnvVar("log-format", "LOG_FORMAT"),
			},
			&cli.BoolFlag{
				Name:        "log-access",
				Usage:       "Enable access logging (disabled by default)",
				Category:    "Logging",
				Destination: &logAccess,
				Sources:     configFileOrEnvVar("log-access", "LOG_ACCESS"),
			},
			&cli.StringFlag{
				Name:        "honey-api-key",
				Usage:       "Optional honeycomb.io key to their Events API",
				Category:    "Logging",
				Destination: &honeyApiKey,
				Sources:     configFileOrEnvVar("honey-api-key", "HONEY_API_KEY"),
			},
			&cli.StringFlag{
				Name:        "honey-dataset",
				Usage:       "Optional honeycomb.io event dataset name",
				Category:    "Logging",
				Destination: &honeyDataset,
				Sources:     configFileOrEnvVar("honey-dataset", "HONEY_DATASET"),
			},
		},
	}

	var exitCode int
	err = app.Run(context.Background(), os.Args)
	if err != nil {
		log.Error("Failed", "err", err)
		exitCode = 1
	} else if showShutdown {
		log.Info("Shutdown")
	}
	if closeLibhoney {
		libhoney.Close()
	}
	os.Exit(exitCode)
}

func startService(ctx context.Context, _ *cli.Command) error {
	showShutdown = true

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := writePidFile(); err != nil {
		return err
	}
	defer removePidFile()

	secrets, err := newSecretStore(ctx)
	if err != nil {
		return err
	}
	defer quiet.Close(secrets)

	limits, err := newLimiterStore()
	if err != nil {
		return err
	}
	defer quiet.CloseWithTimeout(limits.Close, gracefulTimeout)

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           newHandler(secrets, limits),
		ReadHeaderTimeout: time.Minute, // CWE-400 (slowloris) use nginx timeout
	}

	app := runner.New()
	app.CleanupTimeout(server.Shutdown, gracefulTimeout)
	app.Run(func() error { return listenAndServe(ctx, server) })
	return app.Wait()
}

func listenAndServe(ctx context.Context, server *http.Server) error {
	var err error
	ll := log.With("addr", listenAddr)
	if tlsCertFile != "" && tlsKeyFile != "" {
		ll.Info("Starting HTTPS listener")
		err = listenAndServeTLS(ctx, server)
	} else {
		ll.Info("Starting HTTP listener")
		err = server.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func listenAndServeTLS(ctx context.Context, server *http.Server) error {
	loader, err := reloader.New(ctx, tlsCertFile, tlsKeyFile, reloader.WithLogger(log.With("component", "tls")))
	if err != nil {
		return err
	}
	server.TLSConfig = &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: loader.GetCertificate,
	}
	return server.ListenAndServeTLS("", "")
}

func writePidFile() error {
	if pidFilePath == skipPidFile {
		return nil
	}
	log.Info("Creating PID file", "path", pidFilePath)

	fp, err := os.Create(pidFilePath)
	if err != nil {
		return err
	}
	defer fp.Close()

	pid := os.Getpid()
	_, err = fmt.Fprint(fp, strconv.Itoa(pid))
	return err
}

func removePidFile() {
	if pidFilePath != skipPidFile {
		_ = os.Remove(pidFilePath)
	}
}

func setupLogging(ctx context.Context, _ *cli.Command) (context.Context, error) {
	var level log.Level
	switch logLevel {
	case "debug":
		level = log.LevelDebug
	case "warn":
		level = log.LevelWarn
	case "error":
		level = log.LevelError
	default:
		level = log.LevelInfo
	}

	var handler log.Handler
	opts := &log.HandlerOptions{Level: level}
	switch logFormat {
	case "text":
		handler = log.NewTextHandler(os.Stderr, opts)
	case "json":
		handler = log.NewJSONHandler(os.Stderr, opts)
	}
	if honeyApiKey != "" && honeyDataset != "" {
		err := libhoney.Init(libhoney.Config{
			APIKey:  honeyApiKey,
			Dataset: honeyDataset,
		})
		if err != nil {
			return nil, err
		}
		closeLibhoney = true
		events := &honeylogger.Handler{Level: level}
		if handler == nil {
			handler = log.NewTextHandler(os.Stderr, opts)
		}
		handler = log.NewMultiHandler(handler, events)
	}

	args := []any{"build", version}
	if handler != nil {
		log.SetDefault(log.New(handler).With(args...))
	} else {
		log.SetLogLoggerLevel(level)
		log.SetDefault(log.Default().With(args...))
	}
	return ctx, nil
}
