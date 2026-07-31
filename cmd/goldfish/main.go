package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	log "log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/alecthomas/kong"
	kongtoml "github.com/alecthomas/kong-toml"
	"github.com/honeycombio/libhoney-go"
	"github.com/tomcz/gotools/honeylogger"
	"github.com/tomcz/gotools/quiet"
	"github.com/tomcz/gotools/reloader"
	"github.com/tomcz/gotools/runner"
)

// set by build
var version string

const (
	gracefulTimeout  = 100 * time.Millisecond
	skipPidFile      = "skip"
	sqliteStoreType  = "sqlite"
	redisStoreType   = "redis"
	redisTlsOn       = "on"
	redisTlsInsecure = "insecure"
)

type appCfg struct {
	ConfigFile kong.ConfigFlag `short:"c" name:"config" placeholder:"FILE" help:"TOML configuration file."`

	ListenAddr   string  `group:"Application" name:"addr" env:"LISTEN_ADDR" default:"127.0.0.1:3000" help:"Server listen address."`
	PidFilePath  string  `group:"Application" name:"pid-file" env:"PID_FILE" default:"${pname}.pid" help:"PID file path; use 'skip' to disable file creation."`
	BreakerRatio float64 `group:"Application" name:"breaker-ratio" env:"BREAKER_RATIO" default:"0.1" help:"Circuit-breaker failure ratio; use zero or less to disable the circuit-breaker."`
	StoreType    string  `group:"Application" name:"backend" env:"BACKEND_STORE" default:"sqlite" enum:"sqlite,redis" help:"Backend to use for secret storage; either 'sqlite' or 'redis'."`

	TlsCertFile string `group:"HTTPS listener" name:"tls-cert" env:"TLS_CERT_FILE" placeholder:"FILE" type:"existingfile" help:"Server TLS certificate file path."`
	TlsKeyFile  string `group:"HTTPS listener" name:"tls-key" env:"TLS_KEY_FILE" placeholder:"FILE" type:"existingfile" help:"Server TLS private key file path."`

	LimitCount   uint64        `group:"Rate-limiter" name:"limit-count" env:"RATE_LIMIT_COUNT" default:"1000" help:"Maximum number of per-IP requests; use zero to disable the limiter."`
	LimitPeriod  time.Duration `group:"Rate-limiter" name:"limit-period" env:"RATE_LIMIT_PERIOD" default:"1h" help:"Window of time for per-IP requests."`
	LimitHeaders []string      `group:"Rate-limiter" name:"limit-headers" env:"RATE_LIMIT_HEADERS" placeholder:"header" help:"Comma-separated list of HTTP request headers that can provide the remote IP address."`

	StoreSqliteFile  string        `group:"SQLite backend" name:"sqlite-file" env:"SQLITE_FILE" default:"${pname}.db" help:"Database file path."`
	StoreSqliteClean time.Duration `group:"SQLite backend" name:"sqlite-clean" env:"SQLITE_CLEAN" default:"1h" help:"Interval for removal of unaccessed expired secrets."`

	StoreRedisAddr string `group:"Redis backend" name:"redis-addr" env:"REDIS_ADDR" default:"localhost:6379" help:"Redis server address."`
	StoreRedisUser string `group:"Redis backend" name:"redis-user" env:"REDIS_USER" help:"Redis username, if required."`
	StoreRedisPass string `group:"Redis backend" name:"redis-pass" env:"REDIS_PASS" help:"Redis password, if required."`
	StoreRedisDB   int    `group:"Redis backend" name:"redis-db" env:"REDIS_DB" help:"Redis db number, if required."`
	StoreRedisNS   string `group:"Redis backend" name:"redis-ns" env:"REDIS_NS" help:"Redis namespace, if required."`
	StoreRedisTLS  string `group:"Redis backend" name:"redis-tls" env:"REDIS_TLS" default:"off" enum:"off,on,insecure" help:"One of 'off', 'on', or 'insecure'."`

	LogLevel     string `group:"Logging" name:"log-level" env:"LOG_LEVEL" default:"info" enum:"debug,info,warn,error" help:"One of 'debug', 'info', 'warn', or 'error'."`
	LogFormat    string `group:"Logging" name:"log-format" env:"LOG_FORMAT" default:"plain" enum:"plain,text,json" help:"One of 'plain', 'text', or 'json'."`
	LogAccess    bool   `group:"Logging" name:"log-access" env:"LOG_ACCESS" help:"Enable access logging; disabled by default."`
	HoneyApiKey  string `group:"Logging" name:"honey-api-key" env:"HONEY_API_KEY" help:"Optional honeycomb.io key to their Events API."`
	HoneyDataset string `group:"Logging" name:"honey-dataset" env:"HONEY_DATASET" help:"Optional honeycomb.io event dataset name."`

	ShowVersion bool `short:"v" name:"version" help:"Show version and exit."`
}

func main() {
	pname, err := os.Executable()
	if err != nil {
		log.Error("Unable to determine executable path", "err", err)
		os.Exit(1)
	}

	var cfg appCfg
	opts := []kong.Option{
		// we don't expect this file to exist, but we need to configure a loader for the ConfigFile flag to work
		kong.Configuration(kongtoml.Loader, fmt.Sprintf("/etc/goldfish-%s.toml", rand.Text())),
		kong.Description("Webapp for browser-based one-time secret management."),
		kong.Vars{"pname": pname},
	}
	kong.Parse(&cfg, opts...)

	if cfg.ShowVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	closeLibhoney, err := setupLogging(cfg)
	if err != nil {
		log.Error("Failed", "err", err)
		os.Exit(1)
	}

	var exitCode int
	err = startService(cfg)
	if err != nil {
		log.Error("Failed", "err", err)
		exitCode = 1
	} else {
		log.Info("Shutdown")
	}
	if closeLibhoney {
		libhoney.Close()
	}
	os.Exit(exitCode)
}

func startService(cfg appCfg) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := writePidFile(cfg); err != nil {
		return err
	}
	defer removePidFile(cfg)

	secrets, err := newSecretStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer quiet.Close(secrets)

	limits, err := newLimiterStore(cfg)
	if err != nil {
		return err
	}
	defer quiet.CloseWithTimeout(limits.Close, gracefulTimeout)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           newHandler(cfg, secrets, limits),
		ReadHeaderTimeout: time.Minute, // CWE-400 (slowloris) use nginx timeout
	}

	app := runner.New()
	app.CleanupTimeout(server.Shutdown, gracefulTimeout)
	app.Run(func() error { return listenAndServe(ctx, cfg, server) })
	return app.Wait()
}

func listenAndServe(ctx context.Context, cfg appCfg, server *http.Server) error {
	var err error
	ll := log.With("addr", cfg.ListenAddr)
	if cfg.TlsCertFile != "" && cfg.TlsKeyFile != "" {
		ll.Info("Starting HTTPS listener")
		err = listenAndServeTLS(ctx, cfg, server)
	} else {
		ll.Info("Starting HTTP listener")
		err = server.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func listenAndServeTLS(ctx context.Context, cfg appCfg, server *http.Server) error {
	loader, err := reloader.New(ctx, cfg.TlsCertFile, cfg.TlsKeyFile, reloader.WithLogger(log.With("component", "tls")))
	if err != nil {
		return err
	}
	server.TLSConfig = &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: loader.GetCertificate,
	}
	return server.ListenAndServeTLS("", "")
}

func writePidFile(cfg appCfg) error {
	if cfg.PidFilePath == skipPidFile {
		return nil
	}
	log.Info("Creating PID file", "path", cfg.PidFilePath)

	fp, err := os.Create(cfg.PidFilePath)
	if err != nil {
		return err
	}
	defer fp.Close()

	pid := os.Getpid()
	_, err = fmt.Fprint(fp, strconv.Itoa(pid))
	return err
}

func removePidFile(cfg appCfg) {
	if cfg.PidFilePath != skipPidFile {
		_ = os.Remove(cfg.PidFilePath)
	}
}

func setupLogging(cfg appCfg) (bool, error) {
	var level log.Level
	switch cfg.LogLevel {
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
	switch cfg.LogFormat {
	case "text":
		handler = log.NewTextHandler(os.Stderr, opts)
	case "json":
		handler = log.NewJSONHandler(os.Stderr, opts)
	}

	var closeLibhoney bool
	if cfg.HoneyApiKey != "" && cfg.HoneyDataset != "" {
		err := libhoney.Init(libhoney.Config{
			APIKey:  cfg.HoneyApiKey,
			Dataset: cfg.HoneyDataset,
		})
		if err != nil {
			return false, err
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
	return closeLibhoney, nil
}
