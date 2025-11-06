.PHONY: build install clean test run

BINARY_NAME=mvpn
INSTALL_PATH=/usr/local/bin
CONFIG_DIR=/etc/mesh-vpn

build:
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) ./cmd/mvpn

install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_PATH)..."
	sudo install -m 755 $(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Creating config directory at $(CONFIG_DIR)..."
	sudo mkdir -p $(CONFIG_DIR)
	sudo chmod 755 $(CONFIG_DIR)
	@echo "Installation complete!"

uninstall:
	@echo "Removing $(BINARY_NAME) from $(INSTALL_PATH)..."
	sudo rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "Note: Config directory $(CONFIG_DIR) not removed. Remove manually if needed."

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	go clean

test:
	@echo "Running tests..."
	go test -v ./...

run: build
	@echo "Running $(BINARY_NAME)..."
	sudo ./$(BINARY_NAME)

fmt:
	@echo "Formatting code..."
	go fmt ./...

vet:
	@echo "Vetting code..."
	go vet ./...

lint: fmt vet
	@echo "Linting complete!"

deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

help:
	@echo "Available targets:"
	@echo "  build      - Build the binary"
	@echo "  install    - Install the binary to $(INSTALL_PATH)"
	@echo "  uninstall  - Remove the binary from $(INSTALL_PATH)"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Run tests"
	@echo "  run        - Build and run the binary"
	@echo "  fmt        - Format code"
	@echo "  vet        - Vet code"
	@echo "  lint       - Format and vet code"
	@echo "  deps       - Download and tidy dependencies"
	@echo "  help       - Show this help message"