FROM golang:1.26-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o opa-authzen-plugin ./cmd/opa-authzen-plugin

FROM alpine:3.21

RUN addgroup -S opa && adduser -S opa -G opa
COPY --from=builder /build/opa-authzen-plugin /usr/local/bin/opa-authzen-plugin

USER opa

EXPOSE 8181

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -q --spider http://localhost:8181/.well-known/authzen-configuration || exit 1

ENTRYPOINT ["opa-authzen-plugin"]
CMD ["run", "--server"]
