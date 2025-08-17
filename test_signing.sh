#!/bin/bash

echo "🔐 Testing Rust TLS Chat Message Signing System"
echo "================================================"

# Check if certificates exist
if [ ! -f "cert.pem" ] || [ ! -f "key.pem" ]; then
    echo "❌ Certificates not found. Running gencert.sh..."
    ./gencert.sh
fi

echo "✅ Certificates ready"

# Start server in background
echo "🚀 Starting server..."
cargo run --bin chat -- --debug > server.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Check if server is running
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "❌ Server failed to start. Check server.log for details."
    exit 1
fi

echo "✅ Server started (PID: $SERVER_PID)"

# Test client connection and key registration
echo "🔑 Testing client connection and key registration..."
echo "quit" | timeout 10s cargo run --bin client -- --debug > client.log 2>&1

# Check if key registration was successful
if grep -q "Client signing key registered successfully" client.log; then
    echo "✅ Client key registration successful!"
else
    echo "❌ Client key registration failed. Check client.log for details."
fi

# Check if messages were signed
if grep -q "SIGNED:" client.log; then
    echo "✅ Message signing detected!"
else
    echo "❌ No signed messages found. Check client.log for details."
fi

# Check server logs for key registration
if grep -q "Registered client signing key" server.log; then
    echo "✅ Server received client key registration!"
else
    echo "❌ Server didn't receive key registration. Check server.log for details."
fi

# Cleanup
echo "🧹 Cleaning up..."
kill $SERVER_PID 2>/dev/null
wait $SERVER_PID 2>/dev/null

echo ""
echo "📊 Test Results:"
echo "=================="
echo "Server Log: server.log"
echo "Client Log: client.log"
echo ""
echo "🔍 To manually test:"
echo "1. Start server: cargo run --bin chat -- --debug"
echo "2. In another terminal: cargo run --bin client -- --debug"
echo "3. Check for '🔑 Client signing key registered successfully' message"
echo "4. Send messages and verify they appear signed in server logs"
