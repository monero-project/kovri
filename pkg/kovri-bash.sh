# Bash completion for kovri.
# source this script or put it in /usr/share/bash-completion/completions/

########################################
# Searches for short and long options
# starting with "-" and prints them
#
# Globals:
#   None
# Arguments:
#   A line containing options
# Returns:
#   Short option
#   Long option
########################################
_parse_boost_program_options() {
  local short_option long_option w
  for w in $1; do
    case "${w}" in
      -?) [[ -n "${short_option}" ]] || short_option="${w}" ;;
      --*) [[ -n "${long_option}" ]] || long_option="${w}" ;;
    esac
  done

  [[ -n "${short_option}" ]] && printf "%s\n" "${short_option}"
  [[ -n "${long_option}" ]] && printf "%s\n" "${long_option}"
}

########################################
# Parses Boost program options
# generated help description to find
# options
#
# Globals:
#   None
# Arguments:
#   None
# Returns:
#   Options
########################################
_parse_kovri_help() {
  local line
  kovri --help | while read -r line; do
    [[ "${line}" == *-* ]] || continue
    _parse_boost_program_options "${line}"
  done
}

########################################
# Bash completion function for Kovri
#
# Globals:
#   COMPREPLY
# Arguments:
#   None
# Returns:
#   Completion suggestions
########################################
_kovri() {
  local cur prev
  _init_completion -n = || return

  case "${prev}" in
    --host|--port|--service|--httpproxyport|--httpproxyaddress|--socksproxyport| \
    --socksproxyaddress|--i2pcontrolport|--i2pcontroladdress|--i2pcontrolpassword| \
    --reseed-from)
      # An argument is required.
      return
      ;;
    --log-to-file|--log-to-console|--floodfill|-f|--enable-ssu|--enable-ntcp| \
    --daemon)
      COMPREPLY=($(compgen -W "on off yes no true false 1 0" -- "${cur}"))
      return
      ;;
    --log-level)
      COMPREPLY=($(compgen -W "0 1 2 3 4 5" -- "${cur}"))
      return
      ;;
  esac

  # Start parsing the help for option suggestions.
  if [[ "${cur}" == -* ]]; then
    COMPREPLY=($(compgen -W "$(_parse_kovri_help)" -- "${cur}"))
    [[ -n "${COMPREPLY}" ]] && return
  fi

  # Default to input files.
  _filedir
}

complete -F _kovri kovri
