.PHONY: precommit
precommit: clean format lint test compile

.PHONY: format
format:
	goimports -w -local github.com/digitalocean-labs/goldfish .
ifneq ($(shell which npx),)
	npx prettier --print-width 120 --bracket-same-line --write "app/*.(js|css|html)"
endif

.PHONY: lint
lint:
	golangci-lint run --build-tags prod

.PHONY: clean
clean:
	rm -rf target

target:
	mkdir target

.PHONY: test
test:
	go test -v -tags prod ./cmd/...

.PHONY: compile
compile: target
	go build -tags prod -o target/ ./cmd/...

.PHONY: compile-dev
compile-dev: target
	go build -tags dev -o target/ ./cmd/...

.PHONY: run
run: compile
	./target/goldfish

.PHONY: dev
dev: compile-dev
	./target/goldfish

.PHONY: bundle
bundle:
	gzip -k target/goldfish

.PHONY: compile-linux
compile-linux: target
	docker run --rm \
	-e "GOOS=linux" \
	-e "GOARCH=amd64" \
	-e "CGO_ENABLED=1" \
	-v ".:/code" \
	-w "/code" \
	-t golang:1.22.5-bookworm \
	make compile bundle

.PHONY: local-redis
local-redis:
	docker run --rm -e 'ALLOW_EMPTY_PASSWORD=yes' -p "127.0.0.1:6379:6379" -it bitnami/redis:7.4.1
