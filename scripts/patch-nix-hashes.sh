#!/usr/bin/env nix-shell
#!nix-shell -i bash -p gnused gnugrep gawk coreutils
# shellcheck shell=bash

# This script is designed to patch the version and hashes within a default.nix file,
# it is intended to be executed by NSV, as it relies on the NSV environment variables,
# described here: https://docs.purpleclay.dev/nsv/hooks/

: "${DEFAULT_NIX:=${NSV_WORKING_DIRECTORY}/default.nix}"

datefmt() { date +'%Y-%m-%dT%H:%M:%S'; }

GRAY='\033[1;30m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

error() {
  echo -e "${GRAY}$(datefmt) ${RED}ERROR${NC} $*" >&2
  exit 1
}

warn() { echo -e "${GRAY}$(datefmt) ${YELLOW}WARN${NC} $*" >&2; }

info() { echo -e "${GRAY}$(datefmt) ${GREEN}INFO${NC} $*"; }

debug() {
  if [ "${DEBUG}" = "true" ]; then
    echo -e "${GRAY}$(datefmt) ${BLUE}DEBUG${NC} $*"
  fi
}

bye() {
  _result=$?
  rm -f error.log
  exit $_result
}
trap "bye" EXIT

patchVersion() {
  if ! sed -i "s/version = \"[^\"]*\";/version = \"${NSV_NEXT_TAG}\";/" "${DEFAULT_NIX}"; then
    error "Failed to patch version in ${DEFAULT_NIX}"
  fi

  info "Patching version in ${DEFAULT_NIX} to ${NSV_NEXT_TAG}"
}

patchFetchFromGitHubHash() {
  if ! sed -i 's/hash =/# hash =/' "${DEFAULT_NIX}"; then
    error "Failed to comment out hash in ${DEFAULT_NIX}"
  fi

  set +e
  nix build .#default &>error.log
  set -e

  HASH=$(grep -oP '(got|specified):\s+(sha256-\S+)' error.log | awk '{print $2}' | tail -1)
  if [ -z "$HASH" ]; then
    error "Failed to extract hash from error log. Build output:\n$(cat error.log)"
  fi

  if ! sed -i "s|# hash = \"[^\"]*\";|hash = \"${HASH}\";|" "${DEFAULT_NIX}"; then
    error "Failed to patch hash in ${DEFAULT_NIX}"
  fi

  info "Patching hash in ${DEFAULT_NIX} to ${HASH}"
}

patchVendorHash() {
  local vendorField="$1"

  set +e
  nix build .#default &>error.log
  set -e

  HASH=$(grep -oP '(got|specified):\s+(sha256-\S+)' error.log | awk '{print $2}' | tail -1)
  if [ -z "$HASH" ]; then
    error "Failed to extract ${vendorField} from error log. Build output:\n$(cat error.log)"
  fi

  if ! sed -i "s|${vendorField} = \"[^\"]*\";|${vendorField} = \"${HASH}\";|" "${DEFAULT_NIX}"; then
    error "Failed to patch ${vendorField} in ${DEFAULT_NIX}"
  fi

  info "Patching ${vendorField} in ${DEFAULT_NIX} to ${HASH}"
}

if [ ! -f "${DEFAULT_NIX}" ]; then
  error "file ${DEFAULT_NIX} does not exist"
fi

if [ -z "${NSV_NEXT_TAG:-}" ]; then
  error "NSV_NEXT_TAG environment variable is not set"
fi

info "Start patching ${DEFAULT_NIX} ..."

patchVersion
patchFetchFromGitHubHash
if grep -q "vendorHash = " "${DEFAULT_NIX}"; then
  patchVendorHash "vendorHash"
elif grep -q "cargoHash = " "${DEFAULT_NIX}"; then
  patchVendorHash "cargoHash"
else
  error "Neither vendorHash nor cargoHash found in ${DEFAULT_NIX}"
fi

if nix build .#default; then
  info "Successfully patched ${DEFAULT_NIX} 🎉"
else
  error "Failed to patch ${DEFAULT_NIX}"
fi
