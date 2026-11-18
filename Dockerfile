FROM golang:1.26-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o opa-authzen-plugin ./cmd/opa-authzen-plugin

FROM alpine:3.24

# The alpine:3.24 tag lags the 3.24 package index, so packages fixed since the
# tag was cut (zlib 1.4-r0 for CVE-2026-4738, for one) are upgraded here.
# `make image-scan` fails the build if a fixed High or Critical is left.
RUN apk upgrade --no-cache \
 && addgroup -S opa && adduser -S opa -G opa
COPY --from=builder /build/opa-authzen-plugin /usr/local/bin/opa-authzen-plugin

USER opa

EXPOSE 8181

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -q --spider http://localhost:8181/.well-known/authzen-configuration || exit 1

ENTRYPOINT ["opa-authzen-plugin"]
CMD ["run", "--server"]
