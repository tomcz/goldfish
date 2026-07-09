package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"regexp"
	"time"
)

type secretWithTTL struct {
	Secret string
	TTL    time.Duration
}

type secretStore interface {
	setSecret(ctx context.Context, secret *secretWithTTL) (key string, err error)
	getSecret(ctx context.Context, key string) (secret string, err error)
	io.Closer
}

var (
	secretKeyLength   = 42
	secretKeyAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	validSecretKey    = regexp.MustCompile(fmt.Sprintf("^[%s]{%d}$", secretKeyAlphabet, secretKeyLength))
)

func newSecretKey() string {
	alen := byte(len(secretKeyAlphabet))
	key := make([]byte, secretKeyLength)
	_, _ = rand.Read(key)
	for i := range key {
		key[i] = secretKeyAlphabet[key[i]%alen]
	}
	return string(key)
}

func newSecretStore(ctx context.Context) (secretStore, error) {
	switch storeType {
	case sqliteStoreType:
		return newSqliteStore(ctx)
	case redisStoreType:
		return newRedisStore(), nil
	default:
		return nil, fmt.Errorf("unknown backend storage %q", storeType)
	}
}
