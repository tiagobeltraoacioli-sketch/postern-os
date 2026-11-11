#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# postern-vault: encrypted container files (LUKS2) for private data.
#
# A vault is one ordinary file that holds an encrypted ext4 file system. It can
# live on removable media, so a live session can keep private data without
# writing anything readable to a disk. See README.md for the limits.
set -euo pipefail
umask 077

readonly PREFIX=postern-vault
readonly MOUNT_ROOT=/run/postern-vault
readonly MINIMUM_MIB=32
readonly MINIMUM_PASSPHRASE=8

usage() {
  cat <<'EOF'
Usage:
  postern-vault create FILE SIZE [--key-file KEY]   SIZE is e.g. 256M or 4G
  postern-vault open FILE [--key-file KEY] [--read-only]
  postern-vault close NAME|FILE
  postern-vault close --all
  postern-vault list

A vault is an encrypted LUKS2 container file. "open" mounts it at
/run/postern-vault/NAME, where NAME is the file name without its extension.
Without --key-file a passphrase is asked on the terminal (or read as the first
line of standard input when that is not a terminal).

There is no recovery: a lost passphrase or key file means lost data.
EOF
}

die() {
  printf 'postern-vault: %s\n' "$*" >&2
  exit 2
}

as_root() {
  if (( EUID == 0 )); then "$@"; else sudo -- "$@"; fi
}

for tool in cryptsetup mkfs.ext4 mount umount truncate findmnt; do
  command -v "$tool" >/dev/null || die "missing command: $tool"
done
CRYPTSETUP=$(command -v cryptsetup)
MKFS=$(command -v mkfs.ext4)
MOUNT=$(command -v mount)
UMOUNT=$(command -v umount)
MKDIR=$(command -v mkdir)
RMDIR=$(command -v rmdir)

# Vault name from a file path or a bare name: lower-case letters, digits, dashes.
vault_name() {
  local base=${1##*/}
  base=${base%.*}
  base=$(printf '%s' "$base" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9' '-' | sed -e 's/--*/-/g' -e 's/^-//' -e 's/-$//')
  [[ -n $base ]] || die "cannot derive a vault name from '$1'"
  (( ${#base} <= 48 )) || die "vault name is longer than 48 characters"
  printf '%s' "$base"
}

is_open() {
  [[ -e /dev/mapper/$PREFIX-$1 ]]
}

# Sets SECRET from the terminal (asked twice when $1 is "confirm") or from the
# first line of standard input. The passphrase stays in this shell's memory and
# is passed to cryptsetup through a pipe, never as an argument or a file.
read_secret() {
  local again
  if [[ -t 0 ]]; then
    IFS= read -rs -p 'Vault passphrase: ' SECRET; printf '\n' >&2
    if [[ $1 == confirm ]]; then
      IFS= read -rs -p 'Repeat passphrase: ' again; printf '\n' >&2
      [[ $SECRET == "$again" ]] || die 'the passphrases do not match'
    fi
  else
    IFS= read -r SECRET || [[ -n $SECRET ]] || die 'no passphrase on standard input'
  fi
  if [[ $1 == confirm ]] && (( ${#SECRET} < MINIMUM_PASSPHRASE )); then
    die "use a passphrase of at least $MINIMUM_PASSPHRASE characters"
  fi
}

# Runs cryptsetup as root with the key from --key-file or from SECRET on its
# standard input. Options precede the action: nothing after "--" is an option.
with_key() {
  if [[ -n $KEY_FILE ]]; then
    as_root "$CRYPTSETUP" --key-file "$KEY_FILE" "$@"
  else
    printf '%s' "$SECRET" | as_root "$CRYPTSETUP" --key-file - "$@"
  fi
}

parse_options() {
  KEY_FILE=
  READ_ONLY=0
  while (( $# )); do
    case $1 in
      --key-file)
        (( $# >= 2 )) || die '--key-file needs a path'
        KEY_FILE=$2
        [[ -f $KEY_FILE && -r $KEY_FILE ]] || die "key file is not a readable file: $KEY_FILE"
        [[ -s $KEY_FILE ]] || die 'key file is empty'
        shift 2 ;;
      --read-only) READ_ONLY=1; shift ;;
      *) die "unknown option: $1" ;;
    esac
  done
}

command_create() {
  (( $# >= 2 )) || { usage >&2; exit 2; }
  local file=$1 size=$2 megabytes name mapper created=0
  shift 2
  parse_options "$@"
  (( READ_ONLY == 0 )) || die '--read-only does not apply to create'
  [[ $size =~ ^([0-9]{1,6})([MG])$ ]] || die 'SIZE must look like 256M or 4G'
  megabytes=${BASH_REMATCH[1]}
  [[ ${BASH_REMATCH[2]} == M ]] || megabytes=$(( megabytes * 1024 ))
  (( megabytes >= MINIMUM_MIB )) || die "the smallest vault is ${MINIMUM_MIB}M"
  [[ ! -e $file && ! -L $file ]] || die "refusing to overwrite an existing path: $file"
  name=$(vault_name "$file")
  mapper=$PREFIX-$name
  ! is_open "$name" || die "a vault named '$name' is already open"
  SECRET=
  [[ -n $KEY_FILE ]] || read_secret confirm

  cleanup() {
    if (( created )); then
      as_root "$CRYPTSETUP" close "$mapper" 2>/dev/null || true
      rm -f -- "$file"
    fi
  }
  trap cleanup EXIT
  # noclobber: fail instead of following or replacing a path created meanwhile.
  ( set -o noclobber; : > "$file" ) || die "cannot create $file"
  created=1
  truncate -s "${megabytes}M" -- "$file"
  with_key luksFormat --batch-mode --type luks2 --cipher aes-xts-plain64 \
    --key-size 512 --hash sha256 --pbkdf argon2id -- "$file"
  with_key open --type luks2 -- "$file" "$mapper"
  as_root "$MKFS" -q -m 0 -L postern-vault \
    -E "root_owner=${SUDO_UID:-$(id -u)}:${SUDO_GID:-$(id -g)}" "/dev/mapper/$mapper"
  as_root "$CRYPTSETUP" close "$mapper"
  created=0
  trap - EXIT
  printf 'Created %s (%sM, LUKS2, AES-256-XTS, Argon2id).\nOpen it with: postern-vault open %s\n' \
    "$file" "$megabytes" "$file"
}

command_open() {
  (( $# >= 1 )) || { usage >&2; exit 2; }
  local file=$1 name mapper target options=nosuid,nodev arguments=(open --type luks2)
  shift
  parse_options "$@"
  [[ -f $file ]] || die "not a file: $file"
  "$CRYPTSETUP" isLuks --type luks2 -- "$file" || die "not a LUKS2 vault: $file"
  name=$(vault_name "$file")
  mapper=$PREFIX-$name
  target=$MOUNT_ROOT/$name
  ! is_open "$name" || die "'$name' is already open at $target"
  if (( READ_ONLY )); then
    arguments+=(--readonly)
    options+=,ro
  fi
  SECRET=
  [[ -n $KEY_FILE ]] || read_secret once
  with_key "${arguments[@]}" -- "$file" "$mapper" || die 'the vault did not open (wrong passphrase or key file?)'
  if ! { as_root "$MKDIR" -p -m 755 "$MOUNT_ROOT" && as_root "$MKDIR" -p -m 700 "$target" \
         && as_root "$MOUNT" -o "$options" "/dev/mapper/$mapper" "$target"; }; then
    as_root "$RMDIR" "$target" 2>/dev/null || true
    as_root "$CRYPTSETUP" close "$mapper" || true
    die 'the vault opened but its file system did not mount'
  fi
  printf 'Open at %s\nClose it with: postern-vault close %s\n' "$target" "$name"
}

close_one() {
  local name=$1 target=$MOUNT_ROOT/$1
  is_open "$name" || die "no open vault named '$name'"
  if findmnt -n "$target" >/dev/null 2>&1; then
    as_root "$UMOUNT" "$target" || die "$target is busy; close the programs using it"
  fi
  as_root "$CRYPTSETUP" close "$PREFIX-$name"
  as_root "$RMDIR" "$target" 2>/dev/null || true
  printf 'Closed %s\n' "$name"
}

open_names() {
  local device
  shopt -s nullglob
  for device in /dev/mapper/"$PREFIX"-*; do
    printf '%s\n' "${device#/dev/mapper/"$PREFIX"-}"
  done
  shopt -u nullglob
}

command_close() {
  (( $# == 1 )) || { usage >&2; exit 2; }
  local name
  if [[ $1 == --all ]]; then
    while IFS= read -r name; do close_one "$name"; done < <(open_names)
  else
    close_one "$(vault_name "$1")"
  fi
}

command_list() {
  local name any=0
  while IFS= read -r name; do
    any=1
    if findmnt -n "$MOUNT_ROOT/$name" >/dev/null 2>&1; then
      printf '%s\topen at %s\n' "$name" "$MOUNT_ROOT/$name"
    else
      printf '%s\tunlocked, not mounted\n' "$name"
    fi
  done < <(open_names)
  (( any )) || printf 'No vault is open.\n'
}

case ${1:-} in
  create) shift; command_create "$@" ;;
  open) shift; command_open "$@" ;;
  close) shift; command_close "$@" ;;
  list) shift; (( $# == 0 )) || { usage >&2; exit 2; }; command_list ;;
  -h|--help|help) usage ;;
  *) usage >&2; exit 2 ;;
esac
