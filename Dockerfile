FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o ksms main.go

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/ksms .
COPY --from=builder /app/web ./web

EXPOSE 8081

CMD ["./ksms"]
