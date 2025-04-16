APP_NAME := security-demo
IMAGE := ghcr.io/davealtena/$(APP_NAME)
PLATFORMS := linux/amd64,linux/arm64

.PHONY: all build run clean docker-build docker-push

# Default target: build the binary
all: build

# Compile the Go binary
build:
	go build -o $(APP_NAME) .

# Run the binary locally
run: build
	./$(APP_NAME)

# Remove the compiled binary
clean:
	rm -f $(APP_NAME)

# Build and push multi-arch image using Docker Buildx
docker-build:
	docker buildx build \
		--platform $(PLATFORMS) \
		--tag $(IMAGE):latest \
		--file Dockerfile \
		--push \
		.

# Push the image (if already built)
docker-push:
	docker push $(IMAGE):latest

