.PHONY: all server client run-server run-client clean certs help

# Default target
all: server client

# Build targets
server:
	cargo build --bin chat

client:
	cargo build --bin client

# Run targets
run-server: server certs
	./target/debug/chat

runsd:
	./target/debug/chat --debug |tee server.log 2>&1

runs:
	./target/release/chat --debug |tee server.log 2>&1


run-client: client
	./target/debug/client --server localhost --port 8443 --cert cert.pem

# Generate TLS certificates
certs:
	@if [ ! -f cert.pem ] || [ ! -f key.pem ]; then \
		echo "Generating TLS certificates..."; \
		openssl req -x509 -newkey rsa:4096 -keyout temp_key.pem -out cert.pem -days 365 -nodes \
			-subj "/C=US/ST=Test/L=Test/O=Test/CN=localhost"; \
		openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in temp_key.pem -out key.pem; \
		rm temp_key.pem; \
	else \
		echo "TLS certificates already exist."; \
	fi

# Development targets
dev-server: certs
	cargo run --bin chat

dev-client:
	cargo run --bin client

# Both in background (for testing)
demo: certs
	cargo run --bin chat &
	sleep 2
	cargo run --bin client

# Clean targets
clean:
	cargo clean
	rm -f cert.pem key.pem

clean-certs:
	rm -f cert.pem key.pem

# Release builds
release:
	cargo build --release --bin chat
	cargo build --release --bin client

# Help
help:
	@echo "Available targets:"
	@echo "  all         - Build server and client"
	@echo "  server      - Build server only"
	@echo "  client      - Build client only"
	@echo "  run-server  - Build and run server"
	@echo "  run-client  - Build and run client"
	@echo "  dev-server  - Run server with cargo run"
	@echo "  dev-client  - Run client with cargo run"
	@echo "  demo        - Run server in background, then client"
	@echo "  certs       - Generate TLS certificates"
	@echo "  clean       - Remove build artifacts and certificates"
	@echo "  clean-certs - Remove certificates only"
	@echo "  release     - Build optimized release versions"
