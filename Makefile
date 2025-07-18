.PHONY: build install clean test help

# Build the application
build:
	@echo "Building slasher..."
	go build -o slasher slasher.go

# Install the application
install:
	@echo "Installing slasher..."
	go install

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f slasher
	rm -rf builds/

# Run tests (if any)
test:
	@echo "Running tests..."
	go test ./...

# Show help
help:
	@echo "Available targets:"
	@echo "  build   - Build the slasher binary"
	@echo "  install - Install slasher to GOPATH"
	@echo "  clean   - Remove build artifacts"
	@echo "  test    - Run tests"
	@echo "  help    - Show this help message"

# Default target
all: build 