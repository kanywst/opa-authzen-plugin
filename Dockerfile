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

EXPOSE 8181 9292

ENTRYPOINT ["opa-authzen-plugin"]
CMD ["run", "--server"]
