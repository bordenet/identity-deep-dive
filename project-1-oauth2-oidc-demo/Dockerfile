# Multi-stage build for OAuth2/OIDC Authorization Server

# Stage 1: Build
# Use latest Go image to support local Go 1.25.2 development
FROM golang:alpine AS builder

WORKDIR /app

# Copy shared pkg directory first
COPY pkg/ pkg/

# Copy project files
COPY project-1-oauth2-oidc-demo/go.mod project-1-oauth2-oidc-demo/go.sum ./
RUN go mod download

# Copy project source code
COPY project-1-oauth2-oidc-demo/ .

# Build the server binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o authserver ./cmd/server

# Stage 2: Runtime
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy binary from builder
COPY --from=builder /app/authserver .

# Expose port
EXPOSE 8080

# Run the server
CMD ["./authserver"]
