#!/bin/sh
set -eu
exec sh "$(dirname "$0")/deploy/install.sh" "$@"
