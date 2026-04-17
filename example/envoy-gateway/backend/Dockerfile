FROM golang:1.26-alpine AS builder
WORKDIR /build
COPY main.go .
RUN CGO_ENABLED=0 go build -o /backend main.go

FROM alpine:3.21
COPY --from=builder /backend /backend
ENTRYPOINT ["/backend"]
