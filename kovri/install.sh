#!/bin/bash
# TODO(unassigned): /bin/sh isn't smart enough

# Trivial script to install binary/resources using the makeself installer
# Not to substitute real packaging (this is meant for nightly/branch-tip builds)

case "$OSTYPE" in
  linux*)
    _data="$HOME/.kovri"
    _path="$HOME/.bin"
    ;;
  darwin*)
    _data="$HOME/Library/Application Support/Kovri"
    _path="$HOME/Library/Desktop"
    ;;
  freebsd*)
    _data="$HOME/.kovri"
    _path="$HOME/bin"
    ;;
  msys)
    _data="$APPDATA\\Kovri"
    _path="$HOMEPATH\\Desktop"
    ;;
  *)
    echo "Unsupported platform"
    exit 1
    ;;
esac

_backup="${_data}-$(date +%Y.%m.%d)" # TODO(anonimal): we'll probably want to backup using revision hash
_binary="kovri"

# Create bin dir if needed
[ ! -d "$_path" ] && mkdir "$_path"

# Create backup if needed
[ -d "$_data" ] && mv "$_data" "$_backup" && [ -f "${_path}/${_binary}" ] && mv "${_path}/${_binary}" "$_backup"

# Move resources
mkdir "$_data" && mv $(ls -A . | grep -v $(basename "$0")) "$_data" && mv "${_data}/${_binary}" "$_path"

if [ $? -ne 0 ]; then
  echo "Failed to install. See above error messages"
  exit 1
fi

echo "Kovri binary '$_binary' is in $_path"
echo "Consider adding $_path to your \$PATH"
