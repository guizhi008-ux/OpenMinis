#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
TEST_DIR=$(mktemp -d /tmp/openminis-ish-tests.XXXXXX)
trap 'rm -rf "$TEST_DIR"' EXIT HUP INT TERM
for name in local proxy udp udp_ready lifecycle accept_wait; do
    ${CC:-cc} -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror -pthread ${CFLAGS:-} \
        -I. ish_proxy.c "tests/${name}_test.c" -o "$TEST_DIR/$name"
    "$TEST_DIR/$name"
done
