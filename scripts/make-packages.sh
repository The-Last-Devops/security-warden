#!/bin/sh
# Builds .deb and .rpm packages for linux/amd64 and linux/arm64 from the
# binaries in dist/, using nfpm in Docker (nothing to install on the host).
#   scripts/make-packages.sh v0.3.0
set -eu
version=${1#v}
for arch in amd64 arm64; do
  for fmt in deb rpm; do
    # nfpm expands only some fields, so fill the template here.
    sed -e "s/\${VERSION}/$version/g" -e "s/\${ARCH}/$arch/g" packaging/nfpm.yaml > dist/nfpm-$arch.yaml
    docker run --rm -v "$PWD:/w" -w /w goreleaser/nfpm:v2.43.1 \
      package --config "dist/nfpm-$arch.yaml" --packager "$fmt" --target dist/
    rm -f "dist/nfpm-$arch.yaml"
  done
done
ls -l dist/*.deb dist/*.rpm
