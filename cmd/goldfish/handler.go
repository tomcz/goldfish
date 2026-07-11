package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	log "log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/felixge/httpsnoop"
	"github.com/sethvargo/go-limiter"
	"github.com/streadway/handy/breaker"

	"github.com/digitalocean-labs/goldfish/app"
)

type contextKey string

const reqMetadataKey = contextKey("request.metadata")

func newHandler(secrets secretStore, limits limiter.Store) http.Handler {
	mux := http.NewServeMux()
	rate := newRateLimiter(limits)
	mux.Handle("/{$}", http.RedirectHandler("/app/", http.StatusFound))
	mux.Handle("/app/", staticCacheControl(http.StripPrefix("/app", http.FileServer(app.FS))))
	mux.Handle("POST /push", rate.Handle(dynamicCacheControl(setSecret(secrets))))
	mux.Handle("POST /pull", rate.Handle(dynamicCacheControl(getSecret(secrets))))
	mux.Handle("GET /version", dynamicCacheControl(versionHandler()))
	return accessLogger(circuitBreaker(panicRecovery(csrfMiddleware(mux))))
}

func accessLogger(next http.Handler) http.Handler {
	if !logAccess {
		return next
	}
	headers := limitHeadersSlice()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		md := make(map[string]string)
		ctx := context.WithValue(r.Context(), reqMetadataKey, md)

		metrics := httpsnoop.CaptureMetrics(next, w, r.WithContext(ctx))

		fields := []log.Attr{
			log.String("req_host", r.Host),
			log.String("req_method", r.Method),
			log.String("req_uri", r.RequestURI),
			log.String("req_remote_addr", remoteAddr(r, headers)),
			log.String("req_user_agent", r.UserAgent()),
			log.Int64("res_duration_ms", metrics.Duration.Milliseconds()),
			log.Int64("res_duration_ns", metrics.Duration.Nanoseconds()),
			log.Int("res_status", metrics.Code),
		}
		if loc := w.Header().Get("Location"); loc != "" {
			fields = append(fields, log.String("res_location", loc))
		}
		if metrics.Written > 0 {
			fields = append(fields, log.Int64("res_size", metrics.Written))
		}
		for k, v := range md {
			fields = append(fields, log.String(k, v))
		}
		level := statusCodeLevel(metrics.Code)
		log.LogAttrs(context.WithoutCancel(ctx), level, "request", fields...)
	})
}

func remoteAddr(r *http.Request, headers []string) string {
	for _, name := range headers {
		value := r.Header.Get(name)
		if value != "" {
			return value
		}
	}
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}
	return remoteHost
}

func statusCodeLevel(code int) log.Level {
	if code >= 500 {
		return log.LevelError
	}
	if code >= 400 && code != 404 {
		return log.LevelWarn
	}
	return log.LevelInfo
}

func staticCacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := w.Header()
		// Ref: https://web.dev/articles/http-cache
		if app.Embedded {
			if strings.Contains(r.RequestURI, "/lib/") {
				headers.Set("Cache-Control", "max-age=3600, must-revalidate")
			} else {
				headers.Set("Cache-Control", "no-cache")
			}
		} else {
			headers.Set("Cache-Control", "no-store")
		}
		setSecurityHeaders(headers)
		next.ServeHTTP(w, r)
	})
}

func dynamicCacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := w.Header()
		// Ref: https://web.dev/articles/http-cache
		headers.Set("Cache-Control", "no-store")
		setSecurityHeaders(headers)
		next.ServeHTTP(w, r)
	})
}

// Ref: https://blog.appcanary.com/2017/http-security-headers.html
func setSecurityHeaders(headers http.Header) {
	headers.Set("X-XSS-Protection", "1; mode=block")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
}

func circuitBreaker(handler http.Handler) http.Handler {
	if breakerRatio > 0 {
		cb := breaker.NewBreaker(breakerRatio)
		return breaker.Handler(cb, breaker.DefaultStatusCodeValidator, handler)
	}
	return handler
}

func panicRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				stack := string(debug.Stack())
				err := fmt.Errorf("panic: %v; stack: %s", p, stack)
				writeError(w, r, err, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

var csrfSafeMethods = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
}

var csrfSafeFetches = map[string]bool{
	"same-origin": true,
	"none":        true,
}

// adapted from https://github.com/golang/go/issues/73626
func csrfCheck(r *http.Request) error {
	if csrfSafeMethods[r.Method] {
		return nil
	}
	secFetchSite := r.Header.Get("Sec-Fetch-Site")
	if csrfSafeFetches[secFetchSite] {
		return nil
	}
	origin := r.Header.Get("Origin")
	if secFetchSite == "" {
		if origin == "" {
			return errors.New("not a browser request")
		}
		parsed, err := url.Parse(origin)
		if err != nil {
			return fmt.Errorf("bad origin: %w", err)
		}
		if parsed.Host == r.Host {
			return nil
		}
	}
	return fmt.Errorf("Sec-Fetch-Site %q, Origin %q, Host %q", secFetchSite, origin, r.Host)
}

func csrfMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := csrfCheck(r); err != nil {
			writeError(w, r, err, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func getSecret(store secretStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, err := parseGetRequest(r)
		if key == "" {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		secret, err := store.getSecret(r.Context(), key)
		if err != nil {
			writeError(w, r, err, http.StatusInternalServerError)
			return
		}
		if secret == "" {
			http.Error(w, "key not found or expired", http.StatusNotFound)
			return
		}
		writeSuccess(w, secret)
	}
}

func setSecret(store secretStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		secret, err := parseSetRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		key, err := store.setSecret(r.Context(), secret)
		if err != nil {
			writeError(w, r, err, http.StatusInternalServerError)
			return
		}
		writeSuccess(w, key)
	}
}

func parseGetRequest(r *http.Request) (string, error) {
	key := strings.TrimSpace(r.PostFormValue("key"))
	if key == "" {
		return "", errors.New("key is required")
	}
	if !validSecretKey.MatchString(key) {
		return "", errors.New("key is invalid")
	}
	return key, nil
}

func parseSetRequest(r *http.Request) (*secretWithTTL, error) {
	secret := strings.TrimSpace(r.PostFormValue("secret"))
	if secret == "" {
		return nil, errors.New("secret is required")
	}
	if len(secret) > 4096 {
		return nil, errors.New("secret is too long")
	}
	ttlTxt := strings.TrimSpace(r.PostFormValue("ttl"))
	if ttlTxt == "" {
		return nil, errors.New("ttl is required")
	}
	ttlHours, err := strconv.Atoi(ttlTxt)
	if err != nil {
		return nil, errors.New("ttl is invalid")
	}
	if ttlHours < 1 || ttlHours > 72 {
		return nil, errors.New("ttl is too long")
	}
	return &secretWithTTL{
		Secret: secret,
		TTL:    time.Duration(ttlHours) * time.Hour,
	}, nil
}

func versionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeSuccess(w, version)
	}
}

func writeSuccess(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, msg)
}

func writeError(w http.ResponseWriter, r *http.Request, err error, statusCode int) {
	errorID := newErrorID()
	if md, ok := r.Context().Value(reqMetadataKey).(map[string]string); ok {
		md["err_id"] = errorID
		md["err"] = err.Error()
	} else {
		log.LogAttrs(r.Context(), statusCodeLevel(statusCode), "request failed",
			log.String("req_uri", r.RequestURI),
			log.String("req_remote_addr", remoteAddr(r, limitHeadersSlice())),
			log.String("req_user_agent", r.UserAgent()),
			log.Int("res_status", statusCode),
			log.String("err_id", errorID),
			log.String("err", err.Error()),
		)
	}
	http.Error(w, fmt.Sprintf("Error ID: %s", errorID), statusCode)
}

func newErrorID() string {
	buf := make([]byte, 4)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("%x", buf)
}
