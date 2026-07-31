package main

import (
	"crypto/sha256"
	"fmt"
	"net/http"

	"github.com/sethvargo/go-limiter"
	"github.com/sethvargo/go-limiter/httplimit"
	"github.com/sethvargo/go-limiter/memorystore"
	"github.com/sethvargo/go-limiter/noopstore"
	"github.com/sethvargo/go-redisstore"
)

func newRateLimiter(cfg appCfg, store limiter.Store) *httplimit.Middleware {
	mw, err := httplimit.NewMiddleware(store, newLimiterKeyFunc(cfg))
	if err != nil {
		// store and key function are never nil here
		panic(err)
	}
	return mw
}

func newLimiterKeyFunc(cfg appCfg) httplimit.KeyFunc {
	keyFunc := httplimit.IPKeyFunc(cfg.LimitHeaders...)
	if cfg.StoreType != redisStoreType {
		return keyFunc
	}
	return func(r *http.Request) (string, error) {
		key, err := keyFunc(r)
		if err != nil {
			return "", err
		}
		data := sha256.Sum256([]byte(key))
		return redisKey(cfg.StoreRedisNS, "h", fmt.Sprintf("%x", data)), nil
	}
}

func newLimiterStore(cfg appCfg) (limiter.Store, error) {
	if cfg.LimitCount == 0 {
		return noopstore.New()
	}
	if cfg.StoreType != redisStoreType {
		return memorystore.New(&memorystore.Config{
			Tokens:   cfg.LimitCount,
			Interval: cfg.LimitPeriod,
		})
	}
	return redisstore.New(&redisstore.Config{
		Tokens:   cfg.LimitCount,
		Interval: cfg.LimitPeriod,
		Dial:     redisDialFunc(cfg),
	})
}
