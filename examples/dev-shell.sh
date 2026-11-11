#!/bin/bash
# A development shell using sbox's existing mount and network policy.
# Usage: SBOX_BIN=/path/to/sbox ./examples/dev-shell.sh [command [args...]]
# SBOX_WORKSPACE_MODE: bind (default, edits persist), readonly, overlay, or overlay-single.
set -euo pipefail

: "${HOME:?HOME must be set}"
brew_prefix=${HOMEBREW_PREFIX:-/home/linuxbrew/.linuxbrew}
local_bin=$HOME/.local/bin
sbox_bin=${SBOX_BIN:-sbox}

case ${SBOX_WORKSPACE_MODE:-bind} in
    bind) workspace=(-b "$PWD") ;;
    readonly) workspace=(-r "$PWD") ;;
    overlay) workspace=(--overlay "$PWD") ;;
    overlay-single) workspace=(--overlay "$PWD" --overlay-mode single) ;;
    *)
        printf 'dev-shell: SBOX_WORKSPACE_MODE must be bind, readonly, overlay, or overlay-single\n' >&2
        exit 2
        ;;
esac

for dir in "$brew_prefix" "$local_bin"; do
    if [[ ! -d $dir ]]; then
        printf 'dev-shell: required directory does not exist: %q\n' "$dir" >&2
        exit 1
    fi
done

# sbox mounts realpaths. Use those same paths for executable lookup inside.
brew_prefix=$(cd -P -- "$brew_prefix" && pwd -P)
local_bin=$(cd -P -- "$local_bin" && pwd -P)
export PATH="$brew_prefix/bin:$brew_prefix/sbin:$local_bin:/usr/local/bin:/usr/bin:/bin"

for tool in "$sbox_bin" bwrap socat zsh tmux nvim git ssh; do
    if ! command -v -- "$tool" >/dev/null; then
        printf 'dev-shell: required executable is missing: %q\n' "$tool" >&2
        exit 1
    fi
done

if [[ ! -S ${SSH_AUTH_SOCK:-} ]]; then
    printf 'dev-shell: SSH_AUTH_SOCK must name a running SSH agent socket\n' >&2
    exit 1
fi
if [[ ! -f $HOME/.ssh/authorized_keys || ! -r $HOME/.ssh/authorized_keys ]]; then
    printf 'dev-shell: ~/.ssh/authorized_keys must exist and be readable\n' >&2
    exit 1
fi

mounts=(-r "$brew_prefix" -r "$local_bin" -r "$HOME/.ssh/authorized_keys")
# Host keys let git-over-SSH verify servers without exposing private keys.
if [[ -f $HOME/.ssh/known_hosts ]]; then
    mounts+=(-r "$HOME/.ssh/known_hosts")
fi

# /usr (including /usr/bin) and /bin are already read-only system mounts.
# Keep the default private home and tmp. Project writes persist in bind mode.
# Full-screen tmux/nvim need cursor controls, so do not enable --filter-output.
exec "$sbox_bin" \
    "${workspace[@]}" \
    --ssh-agent \
    -a github.com -a git.divar.cloud \
    "${mounts[@]}" \
    -- /bin/sh -eu -c '
        umask 077
        chmod 700 "$HOME/.ssh"
        SHELL=$(command -v zsh)
        export SHELL EDITOR=nvim VISUAL=nvim
        if [ "$#" -eq 0 ]; then
            set -- "$SHELL" -f -i
        fi
        exec "$@"
    ' sbox-dev-shell "$@"
