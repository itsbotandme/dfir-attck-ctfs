#!/usr/bin/env bash
# DFIR CTF launcher — usage: start <ctf-name>
#
# Sources this file (or its function) so 'start' becomes available in your shell:
#     source scripts/start.sh                        # current session only
#     echo "source $(pwd)/scripts/start.sh" >> ~/.bashrc   # permanent
#
# Searches these directories in order:
#   1. The repo's own ./reports/ (relative to where this script lives)
#   2. $HOME/CTFs/
#   3. $HOME/dfir-ctfs/
#
# All CTF HTML files must end with -CTF.html for the launcher to find them.

start() {
  local name="$1"

  # Resolve the repo's reports dir relative to this script's location.
  # Works whether the script was sourced directly or via a path.
  local script_path="${BASH_SOURCE[0]:-$0}"
  local script_dir
  script_dir="$(cd -- "$(dirname -- "$script_path")" >/dev/null 2>&1 && pwd)"
  local repo_reports
  repo_reports="$(cd -- "$script_dir/.." >/dev/null 2>&1 && pwd)/reports"

  local search_dirs=(
    "$repo_reports"
    "$HOME/CTFs"
    "$HOME/dfir-ctfs"
  )

  if [ -z "$name" ] || [ "$name" = "-h" ] || [ "$name" = "--help" ]; then
    echo "Usage: start <ctf-name>"
    echo
    echo "Available CTFs:"
    local found=0
    for dir in "${search_dirs[@]}"; do
      [ -d "$dir" ] || continue
      for f in "$dir"/*-CTF.html; do
        [ -e "$f" ] || continue
        local n
        n=$(basename "$f" -CTF.html)
        printf "  %-30s  %s\n" "$n" "$f"
        found=1
      done
    done
    [ $found -eq 0 ] && echo "  (none found in standard locations)"
    return 0
  fi

  # Exact-name match first
  local ctf_file=""
  for dir in "${search_dirs[@]}"; do
    if [ -f "$dir/${name}-CTF.html" ]; then
      ctf_file="$dir/${name}-CTF.html"
      break
    fi
  done

  # Case-insensitive partial-name match as fallback
  if [ -z "$ctf_file" ]; then
    local name_lc
    name_lc=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')
    for dir in "${search_dirs[@]}"; do
      [ -d "$dir" ] || continue
      for f in "$dir"/*-CTF.html; do
        [ -e "$f" ] || continue
        local base_lc
        base_lc=$(basename "$f" | tr '[:upper:]' '[:lower:]')
        case "$base_lc" in
          *"$name_lc"*) ctf_file="$f"; break 2 ;;
        esac
      done
    done
  fi

  if [ -z "$ctf_file" ]; then
    echo "start: CTF '$name' not found." >&2
    echo "Run 'start' (no args) to list available CTFs." >&2
    return 1
  fi

  echo "Launching CTF: $(basename "$ctf_file")"

  # Cross-platform open
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$ctf_file" >/dev/null 2>&1 &
  elif command -v open >/dev/null 2>&1; then
    open "$ctf_file" >/dev/null 2>&1 &
  elif command -v cmd.exe >/dev/null 2>&1; then
    cmd.exe /c start "" "$ctf_file" >/dev/null 2>&1 &
  else
    echo "start: could not find xdg-open / open / cmd.exe — open manually:" >&2
    echo "  $ctf_file" >&2
    return 1
  fi
}
