FROM golang:1.24-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -o /ext-authz-bridge .

FROM alpine:3.21
COPY --from=builder /ext-authz-bridge /ext-authz-bridge
ENTRYPOINT ["/ext-authz-bridge"]
