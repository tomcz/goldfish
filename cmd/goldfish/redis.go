package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	log "log/slog"
	"time"

	"github.com/gomodule/redigo/redis"
)

type redisStore struct {
	db *redis.Pool
	ns string
}

func newRedisStore(cfg appCfg) secretStore {
	log.Info("Using Redis secret store", "addr", cfg.StoreRedisAddr, "tls", cfg.StoreRedisTLS)
	pool := &redis.Pool{
		MaxIdle:      3,
		IdleTimeout:  2 * time.Minute,
		Dial:         redisDialFunc(cfg),
		TestOnBorrow: redisTestFunc,
	}
	return &redisStore{pool, cfg.StoreRedisNS}
}

func (r *redisStore) Close() error {
	return r.db.Close()
}

func (r *redisStore) setSecret(ctx context.Context, req *secretWithTTL) (string, error) {
	conn := r.db.Get()
	defer conn.Close()

	secretKey := newSecretKey()
	ttl := int64(req.TTL.Seconds())
	_, err := redis.DoContext(conn, ctx, "SET", redisKey(r.ns, "s", secretKey), req.Secret, "EX", ttl)
	if err != nil {
		return "", err
	}
	return secretKey, nil
}

func (r *redisStore) getSecret(ctx context.Context, secretKey string) (string, error) {
	conn := r.db.Get()
	defer conn.Close()

	secret, err := redis.String(redis.DoContext(conn, ctx, "GETDEL", redisKey(r.ns, "s", secretKey)))
	if err != nil {
		if errors.Is(err, redis.ErrNil) {
			return "", nil
		}
		return "", err
	}
	return secret, nil
}

func redisDialFunc(cfg appCfg) func() (redis.Conn, error) {
	return func() (redis.Conn, error) {
		var opts []redis.DialOption
		if cfg.StoreRedisUser != "" {
			opts = append(opts, redis.DialUsername(cfg.StoreRedisUser))
		}
		if cfg.StoreRedisPass != "" {
			opts = append(opts, redis.DialPassword(cfg.StoreRedisPass))
		}
		if cfg.StoreRedisDB > 0 {
			opts = append(opts, redis.DialDatabase(cfg.StoreRedisDB))
		}
		if tlsCfg := redisTLS(cfg); tlsCfg != nil {
			opts = append(opts, redis.DialUseTLS(true), redis.DialTLSConfig(tlsCfg))
		}
		return redis.Dial("tcp", cfg.StoreRedisAddr, opts...)
	}
}

func redisTLS(cfg appCfg) *tls.Config {
	switch cfg.StoreRedisTLS {
	case redisTlsOn:
		return &tls.Config{MinVersion: tls.VersionTLS12}
	case redisTlsInsecure:
		return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	default:
		return nil
	}
}

func redisTestFunc(c redis.Conn, _ time.Time) error {
	_, err := c.Do("PING")
	return err
}

func redisKey(namespace, prefix, key string) string {
	if namespace != "" {
		return fmt.Sprintf("%s:%s:%s", namespace, prefix, key)
	}
	return fmt.Sprintf("%s:%s", prefix, key)
}
