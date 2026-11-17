# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ul3 . \
 && mkdir -p /out/data/files && chown -R 65532:65532 /out/data

FROM scratch
COPY --from=build /out/ul3 /ul3
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV DATA_DIR=/data LISTEN=:8080
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/ul3", "-healthcheck"]
ENTRYPOINT ["/ul3"]
