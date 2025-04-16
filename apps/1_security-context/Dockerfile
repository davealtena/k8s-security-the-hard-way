# Stage 1: Build statically-linked Go binary
FROM golang:1.24 AS builder

WORKDIR /app
COPY . .

# Build without debug symbols to reduce size and attack surface
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o server .

# Stage 2: Minimal runtime image using distroless
FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /app/server .

# Expose port 8080 as used by the Go app
EXPOSE 8080

# Run as non-root (required by distroless:nonroot)
USER nonroot

ENTRYPOINT ["/server"]
