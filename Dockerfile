FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o ksms ./cmd/ksms

FROM alpine:latest

RUN apk add --no-cache curl

WORKDIR /app

COPY --from=builder /app/ksms .
COPY --from=builder /app/web ./web

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8081/healthz || exit 1

CMD ["./ksms"]
