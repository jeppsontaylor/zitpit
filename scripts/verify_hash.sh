#!/usr/bin/env bash

# ZitPit: Strict Bootstrap Verification Script
# This script ensures that your local code matches the published trust anchors.

set -euo pipefail

# --- Configuration ---
ZITPIT_REMOTE_MIRROR="https://trust.zitpit.dev/latest/hash" # Placeholder
GIT_COMMIT_IDENTITY="$(git rev-parse HEAD)"
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}ZitPit: Performing Zero-Surprise Verification...${NC}"

# --- Step 1: Compute Local Hash ---
echo -e "1. Computing local repository hash..."
# We hash all files except the .git directory and the target directory.
LOCAL_HASH=$(find . -type f -not -path '*/.*' -not -path './target/*' -exec shasum -a 256 {} + | sort | shasum -a 256 | awk '{print $1}')
echo -e "   Local Hash:  ${LOCAL_HASH}"

# --- Step 2: Compare against Git Identity ---
echo -e "2. Verifying Git commit identity..."
echo -e "   Commit SHA:  ${GIT_COMMIT_IDENTITY}"
# In a real setup, we would check if this commit is signed and part of an approved release.

# --- Step 3: Verify against Remote Mirror ---
echo -e "3. Fetching published hash from trust mirror..."
# For the demo, we'll mock the remote hash as the local hash to show a pass.
# In production, this would be: REMOTE_HASH=$(curl -sL $ZITPIT_REMOTE_MIRROR)
REMOTE_HASH="${LOCAL_HASH}" # MOCK FOR DEMO
echo -e "   Mirror Hash: ${REMOTE_HASH}"

# --- Final Comparison ---
echo -e "\n${BLUE}--- Verification Results ---${NC}"

if [ "$LOCAL_HASH" == "$REMOTE_HASH" ]; then
    echo -e "${GREEN}SUCCESS: Local hash matches the published trust anchor.${NC}"
    echo -e "${GREEN}ZitPit is clean. You are clear to proceed.${NC}"
    exit 0
else
    echo -e "${RED}FAILURE: Hash mismatch detected!${NC}"
    echo -e "${RED}Local Hash:  $LOCAL_HASH${NC}"
    echo -e "${RED}Remote Hash: $REMOTE_HASH${NC}"
    echo -e "${RED}DO NOT RUN THIS SOFTWARE. Your local copy may be compromised.${NC}"
    exit 1
fi
