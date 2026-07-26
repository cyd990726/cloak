FROM golang:1.26.4-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cloak ./cmd/cloak

FROM alpine:3.20

RUN addgroup -S cloak && adduser -S cloak -G cloak

WORKDIR /app

COPY --from=builder /out/cloak /app/cloak
COPY config.yaml /app/config.yaml
COPY templates /app/templates
COPY data /app/data

ENV CLOAK_HOST=0.0.0.0
ENV CLOAK_PORT=8080

EXPOSE 8080

USER cloak

CMD ["/app/cloak", "-config", "/app/config.yaml"]
