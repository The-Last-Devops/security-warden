# Builds and tests security-warden in a container, so no Go toolchain is
# needed on the host. The scanner itself must run on the host it checks, so
# the "export" stage only outputs binaries.
#
#   docker build --target export --output dist .          # binaries in ./dist
#   docker build --target test .                           # vet + tests
#
# See docker-compose.yml for the day-to-day commands.

ARG GO_VERSION=1.27
ARG NODE_VERSION=22
# What the build stage starts from: "test" (default) gates binaries on the
# tests; releases pass "src" because CI already tested that commit.
ARG BUILD_BASE=test

# ui: the Vue + Tailwind web UI, built once and embedded in the binary.
# Scripts from dependencies never run (--ignore-scripts).
FROM node:${NODE_VERSION}-alpine AS ui
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts --no-audit --no-fund
COPY web/ ./
RUN npm run build

# dev: toolchain only; docker compose mounts the source here.
FROM golang:${GO_VERSION} AS dev
WORKDIR /src
ENV CGO_ENABLED=0 \
    GOFLAGS=-trimpath

# deps: cached module download, invalidated only by go.mod / go.sum.
FROM dev AS deps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# src: the source tree with the built web UI in place.
FROM deps AS src
COPY . .
COPY --from=ui /web/dist/ web/dist/

# test: vet and unit tests, including every rule's sample items, the rule
# check and fix-text lint on every rule, and a check that docs/what-it-checks.md
# and docs/rule-sources.md match the rules and the source schema.
FROM src AS test
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    test -z "$(gofmt -l .)" || { gofmt -l .; echo "run gofmt -w ."; exit 1; }; \
    go vet ./... && GOOS=darwin go vet ./... && GOOS=windows go vet ./... && go test ./... && \
    go run ./tools/gen-rule-docs/main.go -check

# build: cross-compile every target in TARGETS, in parallel.
FROM ${BUILD_BASE} AS build
ARG VERSION=dev
ARG TARGETS="darwin/arm64 darwin/amd64 windows/amd64 linux/amd64 linux/arm64"
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -e; mkdir -p /out; pids=; \
    for t in $TARGETS; do ( \
      set -e; os=${t%/*}; arch=${t#*/}; ext=; [ "$os" = windows ] && ext=.exe; \
      GOOS=$os GOARCH=$arch go build -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/security-warden-$os-$arch$ext ./cmd/security-warden; \
      if [ "$os" != windows ]; then \
        pkg=$(mktemp -d) && cp /out/security-warden-$os-$arch $pkg/security-warden && \
        tar -C $pkg -czf /out/security-warden-$os-$arch.tar.gz security-warden && rm -rf $pkg; \
      fi ) & pids="$pids $!"; \
    done; \
    for p in $pids; do wait $p; done; \
    cd /out && sha256sum security-warden-* > SHA256SUMS

# export: just the binaries, for --output.
FROM scratch AS export
COPY --from=build /out/ /
