#!/bin/bash
# Build script for frontend
# Compiles TypeScript and copies index.html to dist directory

echo "Building frontend..."

# Compile TypeScript
tsc

# Copy index.html from src to dist
if [ -f "src/index.html" ]; then
    cp src/index.html dist/index.html
    echo "Copied index.html to dist/"
else
    echo "Error: src/index.html not found!"
    exit 1
fi

echo "Frontend build complete!"

