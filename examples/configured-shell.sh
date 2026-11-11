#!/bin/bash
# The configured development environment: read-only configuration/tool trees,
# disposable state and project overlays, and the normal interactive terminal.
# Usage: ./examples/configured-shell.sh [command [args...]]
set -euo pipefail

: "${HOME:?HOME must be set}"
brew_prefix=${HOMEBREW_PREFIX:-/home/linuxbrew/.linuxbrew}
export PATH="$brew_prefix/bin:$brew_prefix/sbin:$HOME/.local/bin:${PATH:-/usr/local/bin:/usr/bin:/bin}:/usr/local/bin:/usr/bin:/bin"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
sbox_bin=${SBOX_BIN:-$script_dir/../sbox}
export ZDOTDIR=${ZDOTDIR:-$HOME/.config/zsh}

args=(
    -a github.com -a git.divar.cloud
    --ssh-agent
    --overlay-mode single
    -r "$brew_prefix"
    -r "$HOME/.local/bin"
    -r "$HOME/.ssh/authorized_keys"
    -r "$HOME/.profile"
    -r "$HOME/.zshenv"
    -r "$HOME/.config/nvim"
    -r "$ZDOTDIR"
    -r "$HOME/.config/git"
    -r "$HOME/.config/opencode"
    --overlay "$HOME/.cache"
    --overlay "$HOME/.local/state/zsh"
    --overlay "$HOME/.local/share/antigen"
    --overlay "$HOME/.local/share/go"
    --overlay "$HOME/.local/share/goenv"
    --overlay "$HOME/.local/state/nvim"
    --overlay "$HOME/.local/share/nvim"
    --overlay "$HOME/.local/state/opencode"
    --overlay "$HOME/.local/share/opencode"
    --overlay "$PWD"
    --env ZDOTDIR
    --env SHELL=/bin/zsh
    --env EDITOR=nvim
    --env VISUAL=nvim
)
if [[ -f $HOME/.ssh/known_hosts ]]; then
    args+=(-r "$HOME/.ssh/known_hosts")
fi
for name in TERMINFO TERMINFO_DIRS COLORTERM; do
    if [[ -v $name ]]; then
        args+=(--env "$name")
    fi
done
if (( $# == 0 )); then
    set -- /bin/zsh
fi

exec "$sbox_bin" "${args[@]}" -- /bin/sh -eu -c '
    umask 077
    chmod 700 "$HOME/.ssh"
    exec "$@"
' sbox-configured-shell "$@"
