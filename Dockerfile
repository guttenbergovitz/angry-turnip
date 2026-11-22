# Multi-stage build for minimal image size
FROM golang:1.27-alpine AS builder

# Build arguments for version injection
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build binary with version injection
RUN go build \
    -ldflags "-X github.com/guttenbergovitz/angry-turnip/internal/version.Version=${VERSION} \
              -X github.com/guttenbergovitz/angry-turnip/internal/version.Commit=${COMMIT} \
              -X github.com/guttenbergovitz/angry-turnip/internal/version.Date=${DATE}" \
    -o atnp \
    ./cmd/atnp

# Runtime stage - minimal alpine image
FROM alpine:latest

# Install ca-certificates for HTTPS requests to APIs
RUN apk --no-cache add ca-certificates git

WORKDIR /app

# Copy binary from builder and provide legacy symlink for container backwards compatibility
COPY --from=builder /build/atnp /usr/local/bin/atnp
RUN ln -s /usr/local/bin/atnp /usr/local/bin/vigil && mkdir -p /app/.atnp

# Environment variables (can be overridden at runtime)
ENV NVD_API_KEY=""
ENV GITHUB_TOKEN=""

# Set working directory for scans
WORKDIR /scan

# Default command shows help
ENTRYPOINT ["atnp"]
CMD ["version"]
