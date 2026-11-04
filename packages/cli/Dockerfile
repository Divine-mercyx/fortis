# The Fortis CLI for CI systems and machines that can't install the binary. No Node inside.
#   docker run --rm -v "$PWD:/src" -w /src -e FORTIS_KEY ghcr.io/divine-mercyx/fortis fortis scan --ci
# The release workflow puts the Linux binaries in bin/<arch>/ before building.
FROM debian:bookworm-slim
ARG TARGETARCH
RUN apt-get update -qq \
  && apt-get install -y -qq --no-install-recommends git ca-certificates >/dev/null \
  && rm -rf /var/lib/apt/lists/* \
  # A mounted repository belongs to another user, and git refuses those unless told otherwise.
  && git config --system --add safe.directory '*'
COPY bin/${TARGETARCH}/fortis /usr/local/bin/fortis
CMD ["fortis", "--help"]
