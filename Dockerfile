# Build stage
FROM golang:alpine AS builder

WORKDIR /build

# Copy source
COPY . .

# Build static binary
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o wiimmediamirror .

# Runtime stage
FROM alpine:latest

# Install ca-certificates for HTTPS calls to device APIs
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary and static assets
COPY --from=builder /build/wiimmediamirror .
COPY --from=builder /build/static ./static

# Expose default port
EXPOSE 8080

ENTRYPOINT ["./wiimmediamirror"]
CMD ["8080"]
