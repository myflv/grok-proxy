# Build stage
FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
COPY *.go ./
RUN go build -ldflags="-s -w" -o grok-proxy

# Runtime stage
FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/grok-proxy /usr/local/bin/grok-proxy
WORKDIR /app
EXPOSE 5001
ENTRYPOINT ["grok-proxy", "config.json"]
