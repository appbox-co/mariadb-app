# MySQL (MariaDB) 11.4.13-1 is the released 11.4.13 image with only
# /scripts/run.sh replaced, so MariaDB serves the TLS certificate that Appbox
# mounts at /ssl. The MariaDB 11.4 repository now serves 11.4.14, so a full
# rebuild would change the server version; this keeps 11.4.13's binaries.
#
# Build from the repository root:
#   docker build -f overlays/11.4.13-1/Dockerfile -t repo.cylo.net/mariadb:11.4.13-1 .
FROM repo.cylo.net/mariadb@sha256:96ff7c6ec3ad6f23e003263920f023b7fcf9570e8dbdd42ff1fa761b00db9933

COPY --chmod=755 scripts/run.sh /scripts/run.sh
