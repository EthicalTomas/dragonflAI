#!/usr/bin/env bash
# fetch_nuclei_templates.sh — Clone or fetch nuclei-templates at the pinned commit.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOCK_FILE="${REPO_ROOT}/infra/scanners/templates.lock"
TEMPLATES_DIR="${REPO_ROOT}/infra/scanners/nuclei-templates"

if [ ! -f "${LOCK_FILE}" ]; then
  echo "Error: lock file not found at ${LOCK_FILE}" >&2
  exit 1
fi

TEMPLATES_URL="$(grep '^url=' "${LOCK_FILE}" | cut -d= -f2-)"
PINNED_COMMIT="$(grep '^commit=' "${LOCK_FILE}" | cut -d= -f2-)"

if [ -z "${TEMPLATES_URL}" ] || [ -z "${PINNED_COMMIT}" ]; then
  echo "Error: ${LOCK_FILE} must contain 'url=' and 'commit=' entries." >&2
  exit 1
fi

echo "Templates URL : ${TEMPLATES_URL}"
echo "Pinned commit : ${PINNED_COMMIT}"

if [ -d "${TEMPLATES_DIR}/.git" ]; then
  ACTUAL_URL="$(git -C "${TEMPLATES_DIR}" remote get-url origin 2>/dev/null || true)"
  if [ "${ACTUAL_URL}" != "${TEMPLATES_URL}" ]; then
    echo "Error: existing clone remote '${ACTUAL_URL}' does not match lock URL '${TEMPLATES_URL}'." >&2
    exit 1
  fi
  echo "Repository already cloned — fetching latest objects..."
  git -C "${TEMPLATES_DIR}" fetch --quiet origin
else
  echo "Cloning nuclei-templates..."
  git clone --quiet "${TEMPLATES_URL}" "${TEMPLATES_DIR}"
fi

echo "Checking out pinned commit ${PINNED_COMMIT}..."
git -C "${TEMPLATES_DIR}" checkout --quiet "${PINNED_COMMIT}"

ACTUAL_COMMIT="$(git -C "${TEMPLATES_DIR}" rev-parse HEAD)"
if [ "${ACTUAL_COMMIT}" != "${PINNED_COMMIT}" ]; then
  echo "Error: HEAD commit ${ACTUAL_COMMIT} does not match pinned commit ${PINNED_COMMIT}." >&2
  exit 1
fi

echo "OK — nuclei-templates checked out at ${PINNED_COMMIT}"
