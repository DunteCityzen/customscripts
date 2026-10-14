#!/usr/bin/env bash
# Generate username candidates using BridgeKeeper formatting only.
# No company scraping, API lookup, domain lookup, or network option is used.

set -euo pipefail

PROGRAM_NAME="$(basename "$0")"

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

print_banner() {
    printf '%s\n' \
    '       █▓▒░ genUsernames ░▒▓█ ' \
    '    ▄████▄   ▄████▄   ▄████▄   ▄████▄   ▄████▄ ' \
    '   ███▀▀███  ███▀▀███ ███▀▀███ ███▀▀███ ███▀▀███' \
    '   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███' \
    '   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███' \
    '   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███' \
    '   ▀█████▀   ▀█████▀   ▀█████▀   ▀█████▀   ▀█████▀ ' \
    '             by Mr. Robot.txt'
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------

print_help() {
    cat <<EOF
Usage:
  $PROGRAM_NAME [options] <names_file> [output_dir] [final_list]

Description:
  Generate username candidates from a names file using BridgeKeeper.

  No company scraping, API lookup, domain lookup, or network option is used.

Required:
  names_file
      Input file containing names.

Optional positional arguments:
  output_dir
      Directory where BridgeKeeper writes its generated files.
      Default: out

  final_list
      Final combined username list.
      Default: possibleusernames.txt

Modes:
  --mode full
      Generate every supported username format.

  --mode dot
      Generate every format containing a dot (.).
      This is the DEFAULT mode.

  --mode hyphen
      Generate every format containing a hyphen (-).

  --mode dash
      Generate every format containing an underscore (_).

  --mode nospecchar
      Generate only formats containing no special characters.

Options:
  -m, --mode MODE
      Select the username generation mode.

  --add-domain DOMAIN
      Append @DOMAIN to every generated username.

      Example:
        --add-domain example.com

      Produces:
        john.smith@example.com
        j.smith@example.com
        john.s@example.com

      DOMAIN must not contain @, /, whitespace, or a protocol such as
      http:// or https://.

  --clean-numeric
      Remove username candidates ending in one or more numeric characters
      before creating the final combined list.

      WARNING:
      This removes ANY candidate ending in a number. If legitimate usernames
      can contain numeric suffixes, DO NOT use this option.

  -h, --help
      Show this help message and exit.

Examples:
  $PROGRAM_NAME names.txt

  $PROGRAM_NAME names.txt out possibleusernames.txt

  $PROGRAM_NAME --mode full names.txt

  $PROGRAM_NAME --mode dot names.txt

  $PROGRAM_NAME --mode hyphen names.txt

  $PROGRAM_NAME --mode dash names.txt

  $PROGRAM_NAME --mode nospecchar names.txt

  $PROGRAM_NAME --mode full --clean-numeric names.txt

  $PROGRAM_NAME --mode full --add-domain example.com names.txt

  $PROGRAM_NAME names.txt --add-domain example.com

  $PROGRAM_NAME names.txt out usernames.txt --add-domain example.com

  $PROGRAM_NAME --mode full --clean-numeric \
      --add-domain example.com names.txt out usernames.txt

Modes at a glance:

  full          ALL formats
  dot           Formats containing .
  hyphen        Formats containing -
  dash          Formats containing _
  nospecchar    Formats containing no special character

Default mode:
  dot

Default output directory:
  out

Default final list:
  possibleusernames.txt

EOF
}

# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

die() {
    printf 'Error: %s\n' "$1" >&2
    printf 'Use "%s --help" for usage information.\n' "$PROGRAM_NAME" >&2
    exit 1
}

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

MODE="dot"
CLEAN_NUMERIC=false
DOMAIN=""

# Positional arguments
POSITIONAL=()

# ---------------------------------------------------------------------------
# Command-line parsing
#
# Options may appear anywhere.
#
# Positional arguments:
#   1. names file
#   2. output directory
#   3. final list
# ---------------------------------------------------------------------------

while (($# > 0)); do
    case "$1" in

        -h|--help)
            print_banner
            printf '\n'
            print_help
            exit 0
            ;;

        -m|--mode)
            [[ $# -ge 2 ]] || die "--mode requires a value."
            MODE="$2"
            shift 2
            ;;

        --mode=*)
            MODE="${1#*=}"

            [[ -n "$MODE" ]] || die "--mode requires a value."

            shift
            ;;

        --add-domain)
            [[ $# -ge 2 ]] || die "--add-domain requires a domain."

            DOMAIN="$2"

            [[ -n "$DOMAIN" ]] || die "--add-domain requires a domain."

            shift 2
            ;;

        --add-domain=*)
            DOMAIN="${1#*=}"

            [[ -n "$DOMAIN" ]] || die "--add-domain requires a domain."

            shift
            ;;

        --clean-numeric)
            CLEAN_NUMERIC=true
            shift
            ;;

        --)
            shift

            while (($# > 0)); do
                POSITIONAL+=("$1")
                shift
            done

            break
            ;;

        -*)
            die "Unknown option: $1"

            ;;

        *)
            POSITIONAL+=("$1")
            shift
            ;;

    esac
done

# ---------------------------------------------------------------------------
# No arguments = show help
# ---------------------------------------------------------------------------

if (($# == 0 && ${#POSITIONAL[@]} == 0)); then
    print_banner
    printf '\n'
    print_help
    exit 0
fi

# ---------------------------------------------------------------------------
# Validate positional argument count
# ---------------------------------------------------------------------------

if ((${#POSITIONAL[@]} > 3)); then
    die "Too many positional arguments."
fi

# names_file is required
if ((${#POSITIONAL[@]} < 1)); then
    die "A names file is required."
fi

NAMES_FILE="${POSITIONAL[0]}"
OUTDIR="${POSITIONAL[1]:-out}"
FINAL_LIST="${POSITIONAL[2]:-possibleusernames.txt}"

# ---------------------------------------------------------------------------
# Validate mode
# ---------------------------------------------------------------------------

case "$MODE" in
    full|dot|hyphen|dash|nospecchar)
        ;;
    *)
        die "Invalid mode '$MODE'.

Valid modes:
  full
  dot
  hyphen
  dash
  nospecchar"
        ;;
esac

# ---------------------------------------------------------------------------
# Validate domain
# ---------------------------------------------------------------------------

if [[ -n "$DOMAIN" ]]; then

    # Reject protocol prefixes.
    if [[ "$DOMAIN" == http://* || "$DOMAIN" == https://* ]]; then
        die "Invalid domain '$DOMAIN'. Do not include http:// or https://."
    fi

    # Reject @, slash, whitespace and other characters that should not appear
    # in the domain argument.
    if [[ "$DOMAIN" =~ [^a-zA-Z0-9.-] ]]; then
        die "Invalid domain '$DOMAIN'. Use a domain such as example.com."
    fi

    # Must contain at least one dot.
    if [[ "$DOMAIN" != *.* ]]; then
        die "Invalid domain '$DOMAIN'. Expected a domain such as example.com."
    fi

    # Reject leading/trailing dot.
    if [[ "$DOMAIN" == .* || "$DOMAIN" == *. ]]; then
        die "Invalid domain '$DOMAIN'."
    fi

    # Reject consecutive dots.
    if [[ "$DOMAIN" == *..* ]]; then
        die "Invalid domain '$DOMAIN'."
    fi

    # Reject labels beginning or ending with '-'.
    if [[ "$DOMAIN" == -* || "$DOMAIN" == *- ||
          "$DOMAIN" == *.-* || "$DOMAIN" == *-. ]]; then
        die "Invalid domain '$DOMAIN'."
    fi

fi

# ---------------------------------------------------------------------------
# Check BridgeKeeper
# ---------------------------------------------------------------------------

if ! command -v bridgekeeper >/dev/null 2>&1; then
    die "bridgekeeper is not installed or is not available on PATH."
fi

# ---------------------------------------------------------------------------
# Validate input file
# ---------------------------------------------------------------------------

if [[ ! -f "$NAMES_FILE" ]]; then
    die "Names file does not exist: $NAMES_FILE"
fi

if [[ ! -r "$NAMES_FILE" ]]; then
    die "Names file is not readable: $NAMES_FILE"
fi

if [[ ! -s "$NAMES_FILE" ]]; then
    die "Names file is empty: $NAMES_FILE"
fi

# ---------------------------------------------------------------------------
# Define every supported BridgeKeeper format
# ---------------------------------------------------------------------------

ALL_FORMATS=(
    '{first}{last}'
    '{last}{first}'

    '{first}.{last}'
    '{last}.{first}'

    '{f}{last}'
    '{l}{first}'

    '{f}.{last}'
    '{l}.{first}'

    '{first}.{l}'
    '{last}.{f}'

    '{first}{l}'
    '{last}{f}'

    '{first}_{last}'
    '{last}_{first}'

    '{f}_{last}'
    '{l}_{first}'

    '{first}_{l}'
    '{last}_{f}'

    '{f}_{l}'
    '{l}_{f}'

    '{first}-{last}'
    '{last}-{first}'

    '{f}-{last}'
    '{l}-{first}'

    '{first}-{l}'
    '{last}-{f}'

    '{f}-{l}'
    '{l}-{f}'
)

# ---------------------------------------------------------------------------
# Select formats according to mode
# ---------------------------------------------------------------------------

FORMATS=()

case "$MODE" in

    full)
        FORMATS=("${ALL_FORMATS[@]}")
        ;;

    dot)
        for format in "${ALL_FORMATS[@]}"; do
            [[ "$format" == *.* ]] && FORMATS+=("$format")
        done
        ;;

    hyphen)
        for format in "${ALL_FORMATS[@]}"; do
            [[ "$format" == *-* ]] && FORMATS+=("$format")
        done
        ;;

    dash)
        for format in "${ALL_FORMATS[@]}"; do
            [[ "$format" == *_* ]] && FORMATS+=("$format")
        done
        ;;

    nospecchar)
        for format in "${ALL_FORMATS[@]}"; do
            if [[ "$format" != *.* &&
                  "$format" != *-* &&
                  "$format" != *_* ]]; then
                FORMATS+=("$format")
            fi
        done
        ;;

esac

if ((${#FORMATS[@]} == 0)); then
    die "No username formats were selected."
fi

# ---------------------------------------------------------------------------
# Prepare output directory
# ---------------------------------------------------------------------------

if [[ -e "$OUTDIR" ]]; then

    [[ -d "$OUTDIR" ]] || \
        die "Output path exists but is not a directory: $OUTDIR"

    if find "$OUTDIR" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
        die "Output directory is not empty: $OUTDIR

BridgeKeeper output must be written into an empty directory.
Remove its previous contents or choose another output directory."
    fi

else
    mkdir -p "$OUTDIR"
fi

# ---------------------------------------------------------------------------
# Prevent accidental overwrite of existing final list
# ---------------------------------------------------------------------------

if [[ -e "$FINAL_LIST" ]]; then
    die "Final output already exists: $FINAL_LIST

Remove it first or specify a different final_list."
fi

# ---------------------------------------------------------------------------
# Display configuration
# ---------------------------------------------------------------------------

print_banner

printf '\n'
printf '%s\n' 'Configuration'
printf '%s\n' '-------------'
printf 'Mode:          %s\n' "$MODE"
printf 'Names file:    %s\n' "$NAMES_FILE"
printf 'Output dir:    %s\n' "$OUTDIR"
printf 'Final list:    %s\n' "$FINAL_LIST"
printf 'Formats:       %d\n' "${#FORMATS[@]}"

if [[ -n "$DOMAIN" ]]; then
    printf 'Domain:        %s\n' "$DOMAIN"
else
    printf 'Domain:        none\n'
fi

printf 'Numeric clean: %s\n' "$CLEAN_NUMERIC"
printf '\n'

if "$CLEAN_NUMERIC"; then
    printf '%s\n' \
        'WARNING: --clean-numeric is enabled.' \
        'Any generated username ending in one or more digits will be removed.' \
        'Do NOT use this option if legitimate usernames can contain numeric suffixes.' \
        ''
fi

# ---------------------------------------------------------------------------
# Convert selected formats to BridgeKeeper comma-separated argument
# ---------------------------------------------------------------------------

format_csv=$(IFS=,; printf '%s' "${FORMATS[*]}")

# ---------------------------------------------------------------------------
# Run BridgeKeeper
# ---------------------------------------------------------------------------

printf 'Running BridgeKeeper...\n\n'

bridgekeeper \
    --names "$NAMES_FILE" \
    --format "$format_csv" \
    --lower \
    --output "$OUTDIR"

# ---------------------------------------------------------------------------
# Collect BridgeKeeper output
# ---------------------------------------------------------------------------

shopt -s nullglob
OUTPUT_FILES=("$OUTDIR"/*)

if ((${#OUTPUT_FILES[@]} == 0)); then
    die "BridgeKeeper completed but did not create any output files."
fi

# ---------------------------------------------------------------------------
# Create temporary list
# ---------------------------------------------------------------------------

TMP_LIST="$(mktemp)"

cleanup() {
    rm -f "$TMP_LIST"
}

trap cleanup EXIT

if "$CLEAN_NUMERIC"; then

    for file in "${OUTPUT_FILES[@]}"; do
        sed -E '/[0-9]+$/d' "$file"
    done > "$TMP_LIST"

else

    cat "${OUTPUT_FILES[@]}" > "$TMP_LIST"

fi

# ---------------------------------------------------------------------------
# Add domain if requested
# ---------------------------------------------------------------------------

if [[ -n "$DOMAIN" ]]; then

    # Append @domain to every non-empty generated username.
    sed -E "s|^(.+)$|\1@$DOMAIN|" "$TMP_LIST" > "$FINAL_LIST"

else

    cat "$TMP_LIST" > "$FINAL_LIST"

fi

# ---------------------------------------------------------------------------
# Final validation
# ---------------------------------------------------------------------------

if [[ ! -s "$FINAL_LIST" ]]; then
    rm -f "$FINAL_LIST"
    die "The final username list is empty."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

CANDIDATE_COUNT="$(wc -l < "$FINAL_LIST")"

printf '\n'
printf '%s\n' 'Generation complete.'
printf '%s\n' '-------------------'
printf 'Mode:             %s\n' "$MODE"
printf 'Format files:     %d\n' "${#OUTPUT_FILES[@]}"
printf 'Username entries: %s\n' "$CANDIDATE_COUNT"

if [[ -n "$DOMAIN" ]]; then
    printf 'Domain appended:  @%s\n' "$DOMAIN"
fi

printf 'Final list:       %s\n' "$FINAL_LIST"
printf '\n'
