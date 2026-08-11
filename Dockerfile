# syntax=docker/dockerfile:1

FROM golang:1.20-alpine AS builder

WORKDIR /src
RUN apk add --no-cache ca-certificates git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth-server ./cmd/auth-server

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 app

WORKDIR /app

COPY --from=builder /out/auth-server .
COPY configs/config.docker.yaml ./configs/config.yaml
RUN mkdir -p uploads && chown -R app:app /app

USER app

EXPOSE 8888

ENTRYPOINT ["./auth-server"]
