#!/usr/bin/env bash
set -euo pipefail

# Defaults
DEFAULT_ACCEPT="js"
DEFAULT_LEVEL=5

usage() {
  cat <<EOF
Usage: $(basename "$0") [-t TARGET] [-o OUTDIR] [-a ACCEPT] [-l LEVEL] [-h]
  -t TARGET   Target URL to crawl (e.g. https://example.com). Can also be provided as first positional arg.
  -o OUTDIR   Output directory (default: ./collected-js). Can also be provided as second positional arg.
  -a ACCEPT   Comma-separated accept list for wget (default: $DEFAULT_ACCEPT)
  -l LEVEL    Recursion level for wget (default: $DEFAULT_LEVEL)
  -h          Show this help and exit

Examples:
  $(basename "$0") -t "https://example.com" -o "./out"
  $(basename "$0") "https://example.com" "./out"
EOF
}

# Parse options
TARGET=""
OUTDIR=""
ACCEPT="$DEFAULT_ACCEPT"
LEVEL="$DEFAULT_LEVEL"

while getopts ":t:o:a:l:h" opt; do
  case $opt in
    t) TARGET="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    a) ACCEPT="$OPTARG" ;;
    l) LEVEL="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage; exit 2 ;;
    :) echo "Option -$OPTARG requires an argument." >&2; usage; exit 2 ;;
  esac
done
shift $((OPTIND -1))

# Positional fallback
if [[ -z "$TARGET" && $# -ge 1 ]]; then
  TARGET="$1"
fi
if [[ -z "$OUTDIR" && $# -ge 2 ]]; then
  OUTDIR="$2"
fi

# Validation
if [[ -z "$TARGET" ]]; then
  echo "Error: TARGET not provided." >&2
  usage
  exit 2
fi

# simple URL check (must start with http:// or https://)
if ! [[ "$TARGET" =~ ^https?:// ]]; then
  echo "Error: TARGET must start with http:// or https:// (got: $TARGET)" >&2
  exit 2
fi

# default outdir
if [[ -z "$OUTDIR" ]]; then
  OUTDIR="./collected-js"
fi

# ensure wget exists
if ! command -v wget >/dev/null 2>&1; then
  echo "Error: wget not found in PATH. Please install wget." >&2
  exit 3
fi

# Create output dir
mkdir -p "$OUTDIR"

# Run wget
echo "Crawling: $TARGET"
echo "Saving to: $OUTDIR"
echo "Accept types: $ACCEPT"
echo "Recursion level: $LEVEL"
echo

# The wget flags:
#  --recursive            : recursive download
#  --no-clobber           : don't overwrite existing files
#  --page-requisites      : get CSS/JS/images required to display pages
#  --adjust-extension     : save files with proper extensions
#  --span-hosts           : be allowed to visit other hosts for required elements
#  --convert-links        : convert links for local viewing
#  --no-parent            : do not ascend to parent directories
#  --accept               : accept only specified extensions (comma separated)
#  --level                : maximum recursion depth (useful to avoid crawling entire web)
wget --recursive --no-clobber --page-requisites --adjust-extension \
  --span-hosts --convert-links --no-parent --accept="$ACCEPT" --level="$LEVEL" \
  --directory-prefix="$OUTDIR" "$TARGET"
