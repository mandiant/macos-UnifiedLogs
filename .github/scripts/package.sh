#!/usr/bin/env bash
set -eu

# Slightly tweaked from https://github.com/EmbarkStudios/cargo-about/blob/main/.github/workflows/rust-ci.yml (MIT or APACHE 2.0)
# When run in a container, the ownership will be messed up, so mark the
# checkout dir as safe regardless of our env
git config --global --add safe.directory "$GITHUB_WORKSPACE"

# Normally we'll only do this on tags, but add --always to fallback to the revision
# if we're iterating or the like
tag=$(git describe --tags --abbrev=0 --always)

if [[ ${tag:0:1} != "v" ]]; then
  tag="nightly"
fi

release_name="$NAME-$tag-$TARGET"
release_zip="${release_name}.zip"
release_tar="${release_name}.tar.gz"

mkdir "$release_name"

if [[ "$TARGET" =~ windows ]]; then
    bin="$NAME.exe"
    cp "examples/target/release/$bin" "$release_name/"
    cp README.md LICENSE "$release_name/"
    7z a -tzip "$release_zip" "$release_name"
else
    bin="$NAME"
    cp "examples/target/release/$bin" "$release_name/"
    cp README.md LICENSE "$release_name/"
    tar czf "$release_tar" "$release_name"
fi

rm -r "$release_name"

# Windows environments in github actions don't have the gnu coreutils installed,
# which includes the shasum exe, so we just use powershell instead
if [[ "$TARGET" =~ windows ]]; then
    echo "(Get-FileHash \"${release_zip}\" -Algorithm SHA256).Hash | Out-File -Encoding ASCII -NoNewline \"${release_zip}.sha256\"" | pwsh -c -
else
    echo -n "$(shasum -ba 256 "${release_tar}" | cut -d " " -f 1)" > "${release_tar}.sha256"
fi