# Builds and tests security-warden in a container, so no Go toolchain is
# needed on the host. The scanner itself must run on the host it checks, so
# the "export" stage only outputs binaries.
#
#   docker build --target export --output dist .          # binaries in ./dist
#   docker build --target test .                           # vet + tests
#
# See docker-compose.yml for the day-to-day commands.

ARG GO_VERSION=1.27

# dev: toolchain only; docker compose mounts the source here.
FROM golang:${GO_VERSION} AS dev
WORKDIR /src
ENV CGO_ENABLED=0 \
    GOFLAGS=-trimpath

# deps: cached module download, invalidated only by go.mod / go.sum.
FROM dev AS deps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# test: vet and unit tests, including every rule's sample items.
FROM deps AS test
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    test -z "$(gofmt -l .)" || { gofmt -l .; echo "run gofmt -w ."; exit 1; }; \
    go vet ./... && GOOS=darwin go vet ./... && GOOS=windows go vet ./... && go test ./...

# build: cross-compile for macOS (arm64 + amd64) and Windows (amd64).
FROM test AS build
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    set -e; \
    for t in darwin/arm64 darwin/amd64 windows/amd64 linux/amd64 linux/arm64; do \
      os=${t%/*}; arch=${t#*/}; ext=; [ "$os" = windows ] && ext=.exe; \
      GOOS=$os GOARCH=$arch go build -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/security-warden-$os-$arch$ext ./cmd/security-warden; \
    done; \
    cd /out && sha256sum security-warden-* > SHA256SUMS

# export: just the binaries, for --output.
FROM scratch AS export
COPY --from=build /out/ /
