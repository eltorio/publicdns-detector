# Builder stage
FROM golang:1.21 AS builder

WORKDIR /app

COPY main.go .
COPY go.mod .
COPY go.sum .

RUN go mod tidy
RUN go build -o publicdns-detector main.go

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

COPY templates /app/templates
COPY static /app/static
COPY --from=builder /app/publicdns-detector /app/publicdns-detector

ENTRYPOINT ["/app/publicdns-detector"]
