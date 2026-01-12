#!/usr/bin/env bash
set -eu

export PORT=8095

# Start TypeScript RPC server in background using tsx (no build needed)
echo "Starting TypeScript RPC server on port ${PORT}..."
yarn dev &
TS_SERVER_PID=$!

# Trap to kill server on exit (only if process exists)
trap 'kill $TS_SERVER_PID 2>/dev/null || true' EXIT

# Wait for server to start
echo "Waiting for server to be ready..."
sleep 3

project_dir="$(dirname "$0")/.."

# Run the Noir tests with oracle resolver
echo "Running Noir tests with oracle..."
nargo --program-dir="$project_dir" test --oracle-resolver http://localhost:${PORT}

echo "Running Noir tests with force-brillig..."
nargo --program-dir="$project_dir" test --oracle-resolver http://localhost:${PORT} --force-brillig
