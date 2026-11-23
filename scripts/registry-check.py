#!/usr/bin/env python3
"""Fail closed unless the authenticated registry confirms this new tag is absent."""
import subprocess
import sys

EXPECTED = 'repo.cylo.net/mariadb:11.4.13-1'
# The image `latest` pointed at when 11.4.13 was built (11.4.9 in the
# catalogue, MariaDB 11.4.10 inside, still offered). The test-account upgrade
# tests start from it.
CURRENT = 'repo.cylo.net/mariadb@sha256:d82d8e84aa1ebbf4d5fa1f5611fc482b0dc333f747293f705a7a00cca19a8208'
# The released 11.4.13 image (the catalogue default when 11.4.13-1 was
# built). 11.4.13-1 is built on it, and the TLS tests upgrade from it.
PREVIOUS = 'repo.cylo.net/mariadb@sha256:96ff7c6ec3ad6f23e003263920f023b7fcf9570e8dbdd42ff1fa761b00db9933'


def require_absent(image):
    if image != EXPECTED:
        raise RuntimeError('Unexpected image reference')
    for baseline in (CURRENT, PREVIOUS):
        known = subprocess.run(['docker', 'manifest', 'inspect', baseline], capture_output=True, text=True,
                               timeout=90)
        if known.returncode:
            raise RuntimeError('Authenticated registry baseline read failed; state is indeterminate')
    result = subprocess.run(['docker', 'manifest', 'inspect', image], capture_output=True, text=True, timeout=90)
    if result.returncode == 0:
        raise RuntimeError('Release tag exists; refusing replacement')
    if result.stderr.strip() != 'no such manifest: ' + image:
        raise RuntimeError('Registry response is indeterminate; refusing publication')
    print('PASS registry: baseline readable and exact release tag definitively absent', flush=True)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: registry-check.py IMAGE')
    require_absent(sys.argv[1])
