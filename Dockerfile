FROM golang:1.26.7-alpine3.23 AS builder

WORKDIR /app

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -buildvcs=false \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/volcano-cert-sync ./cmd/sync

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder --chown=65532:65532 /out/volcano-cert-sync /volcano-cert-sync

USER 65532:65532
ENTRYPOINT ["/volcano-cert-sync"]
