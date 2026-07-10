GITCOMMIT := $(shell git rev-parse --short=7 HEAD 2>/dev/null)

.PHONY: precommit
precommit: clean tidy format lint test compile

.PHONY: format
format:
	golangci-lint fmt
ifneq ($(shell which npx),)
	npx prettier --print-width 120 --bracket-same-line --write "app/*.(js|css|html)"
endif

.PHONY: tidy
tidy:
	go mod tidy

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
	go build -tags prod -ldflags "-s -w -X main.version=${GITCOMMIT}" -o target/ ./cmd/...

.PHONY: compile-dev
compile-dev: target
	go build -tags dev -ldflags "-s -w -X main.version=${GITCOMMIT}" -o target/ ./cmd/...

.PHONY: run
run: compile
	./target/goldfish

.PHONY: dev
dev: compile-dev
	./target/goldfish

.PHONY: bundle
bundle:
	gzip -k target/goldfish

.PHONY: local-redis
local-redis:
	docker-compose up redis

.PHONY: docker-run
docker-run: container
	docker-compose up

.PHONY: container
container:
	docker build --platform linux/amd64 --build-arg "GITCOMMIT=${GITCOMMIT}" --tag localhost/goldfish .

.PHONY: publish
publish: container
ifdef REGISTRY_ENDPOINT
	docker tag localhost/goldfish:latest ${REGISTRY_ENDPOINT}/goldfish:${GITCOMMIT}
	docker tag localhost/goldfish:latest ${REGISTRY_ENDPOINT}/goldfish:latest
	docker push ${REGISTRY_ENDPOINT}/goldfish:${GITCOMMIT}
	docker push ${REGISTRY_ENDPOINT}/goldfish:latest
else
	$(error "Please define a REGISTRY_ENDPOINT")
endif

.PHONY: registry-login
registry-login:
ifdef REGISTRY_NAME
	doctl registries login ${REGISTRY_NAME} --expiry-seconds 600
else
	$(error "Please define a REGISTRY_NAME")
endif

.PHONY: verify
verify:
	./verify.sh ${GITCOMMIT}
