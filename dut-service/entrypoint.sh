#!/bin/sh
set -e
/usr/sbin/sshd
exec /sbin/tini -- /usr/lib/frr/docker-start
