#!/usr/bin/env bash
# Install system dependencies needed by a given crypt-sha512 backend.
#
# Usage: install-backend-deps.sh <backend-feature> <linux|macos|windows>
#
# - backend-aws-lc:       cmake (+ a C compiler, assumed present)
# - backend-boring:       cmake, ninja, go, C/C++ compiler
# - backend-openssl:      OpenSSL development headers
# - backend-rust-crypto:  nothing
set -euo pipefail

backend="${1:?backend feature required}"
platform="${2:?platform required (linux|macos|windows)}"

echo "Installing deps for backend=$backend on platform=$platform"

case "$backend" in
  backend-aws-lc)
    case "$platform" in
      linux)   sudo apt-get update && sudo apt-get install -y cmake ;;
      macos)   brew install cmake ;;
      windows) choco install cmake --installargs 'ADD_CMAKE_TO_PATH=System' ;;
    esac
    ;;
  backend-boring)
    case "$platform" in
      linux)
        sudo apt-get update
        sudo apt-get install -y cmake ninja-build golang
        ;;
      macos)
        brew install cmake ninja go
        ;;
      windows)
        choco install cmake ninja golang --installargs 'ADD_CMAKE_TO_PATH=System'
        ;;
    esac
    ;;
  backend-openssl)
    case "$platform" in
      linux)   sudo apt-get update && sudo apt-get install -y libssl-dev pkg-config ;;
      macos)   brew install openssl@3 pkg-config ;;
      windows) vcpkg install openssl:x64-windows-static-md ;;
    esac
    ;;
  backend-rust-crypto)
    echo "No system deps required."
    ;;
  *)
    echo "Unknown backend: $backend" >&2
    exit 1
    ;;
esac
