#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 10 ]]; then
  echo "Usage: package.sh <repo> <publish> <key.pem> <key-id> <version> <os> <arch> <revision> <executable> <output>" >&2
  exit 2
fi

repository="$(cd "$1" && pwd)"
publish="$(cd "$2" && pwd)"
key="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
key_id="$4"
version="$5"
target_os="$6"
target_arch="$7"
revision="$8"
executable="$9"
output="$(cd "$(dirname "${10}")" && pwd)/$(basename "${10}")"

[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]
[[ "$target_os" =~ ^(linux|macos)$ ]]
[[ "$target_arch" =~ ^(x64|arm64)$ ]]
[[ "$revision" =~ ^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$ ]]
[[ -f "$key" && -n "$key_id" ]]

stage="$(mktemp -d)"
trap 'rm -rf -- "$stage"' EXIT
mkdir -p "$stage/runtime/process" "$stage/manifest" "$stage/signature"
find "$publish" -maxdepth 1 -type f ! -name '*.pdb' -exec cp {} "$stage/runtime/process/" \;
cp -R "$repository/schemas" "$stage/schemas"
cp -R "$repository/sbom" "$stage/sbom"
cp -R "$repository/provenance" "$stage/provenance"
if [[ -d "$repository/client" ]]; then
  cp -R "$repository/client" "$stage/client"
  while IFS= read -r -d '' client_file; do
    jq --arg version "$version" '.extension.version=$version' "$client_file" > "$client_file.release"
    mv "$client_file.release" "$client_file"
    client_payload="$(jq -cS '.extension' "$client_file")"
    client_signature="$(printf '%s' "$client_payload" | openssl dgst -sha256 -sign "$key" | base64 | tr -d '\n')"
    jq --arg keyId "$key_id" --arg signature "$client_signature" '.signature.keyId=$keyId | .signature.value=$signature' "$client_file" > "$client_file.release"
    mv "$client_file.release" "$client_file"
  done < <(find "$stage/client" -type f -name '*.json' -print0)
fi
for contribution in configuration migrations; do
  if [[ -d "$repository/$contribution" ]]; then cp -R "$repository/$contribution" "$stage/$contribution"; fi
done

entrypoint="runtime/process/$executable"
[[ -f "$stage/$entrypoint" ]]
artifact_digest="sha256:$(sha256sum "$stage/$entrypoint" | cut -d' ' -f1)"
awk -v version="$version" -v target_os="$target_os" -v target_arch="$target_arch" -v entrypoint="$entrypoint" -v digest="$artifact_digest" '
  /^metadata:/ { metadata=1 }
  /^compatibility:/ { metadata=0 }
  metadata && /^metadata: \{/ { sub(/version: [^,}]+/, "version: " version) }
  metadata && /^  version:/ { print "  version: " version; next }
  /entrypoint: runtime\/process\// && /mode: process/ {
    gsub(/os: \[[^]]*\]/, "os: [" target_os "]")
    gsub(/architectures: \[[^]]*\]/, "architectures: [" target_arch "]")
    sub(/entrypoint: runtime\/process\/[^, }]+/, "entrypoint: " entrypoint)
    sub(/digest: "sha256:[a-f0-9]+"/, "digest: \"" digest "\"")
    runtime_patched=1
  }
  /^      os:/ && !runtime_patched { print "      os: [" target_os "]"; next }
  /^      architectures:/ && !runtime_patched { print "      architectures: [" target_arch "]"; next }
  /^      entrypoint: runtime\/process\// && !runtime_patched { print "      entrypoint: " entrypoint; next }
  /^      digest:/ && !runtime_patched { print "      digest: " digest; runtime_patched=1; next }
  { print }
' "$repository/murchalka.module.yaml" > "$stage/manifest/murchalka.module.yaml"

client_entrypoint="$(sed -nE 's/.*entrypoint: (client\/[^, }]+).*/\1/p' "$stage/manifest/murchalka.module.yaml" | head -1)"
client_id=""
client_digest=""
if [[ -n "$client_entrypoint" ]]; then
  client_id="$(sed -nE 's/^[[:space:]]*- \{ id: ([^,]+), extensionId:.*/\1/p' "$stage/manifest/murchalka.module.yaml" | head -1)"
  client_digest="sha256:$(sha256sum "$stage/$client_entrypoint" | cut -d' ' -f1)"
  awk -v version="$version" -v digest="$client_digest" '
    /entrypoint: client\// {
      sub(/extensionVersion: [^,}]+/, "extensionVersion: " version)
      sub(/digest: "sha256:[a-f0-9]+"/, "digest: \"" digest "\"")
    }
    { print }
  ' "$stage/manifest/murchalka.module.yaml" > "$stage/manifest/murchalka.module.release.yaml"
  mv "$stage/manifest/murchalka.module.release.yaml" "$stage/manifest/murchalka.module.yaml"
fi

module_id="$(sed -nE 's/^metadata: \{ id: ([^,]+),.*/\1/p' "$stage/manifest/murchalka.module.yaml" | head -1)"
if [[ -z "$module_id" ]]; then module_id="$(awk '/^metadata:/{metadata=1;next} metadata && /^  id:/{print $2;exit}' "$stage/manifest/murchalka.module.yaml")"; fi
artifact_id="$(sed -nE 's/^[[:space:]]*- \{ id: ([^,]+), mode: process,.*/\1/p' "$stage/manifest/murchalka.module.yaml" | head -1)"
contracts='[]'
while IFS='|' read -r capability_id capability_version contract_path; do
  [[ -n "$capability_id" && -f "$stage/$contract_path" ]]
  contract_digest="sha256:$(sha256sum "$stage/$contract_path" | cut -d' ' -f1)"
  contracts="$(jq -c --arg id "$capability_id" --arg version "$capability_version" --arg digest "$contract_digest" '. + [{id:$id,version:$version,schemaDigest:$digest}]' <<< "$contracts")"
done < <(sed -n '/^provides:/,/^[a-z]/p' "$stage/manifest/murchalka.module.yaml" | sed -nE 's/^[[:space:]]*- \{ id: ([^,]+), category: [^,]+, version: ([^,]+), contract: ([^,]+),.*/\1|\2|\3/p')
[[ "$(jq length <<< "$contracts")" -gt 0 ]]

artifacts="$(jq -c -n --arg id "$artifact_id" --arg digest "$artifact_digest" '[{target:"runtime",id:$id,digest:$digest}]')"
if [[ -n "$client_id" ]]; then
  artifacts="$(jq -c --arg id "$client_id" --arg digest "$client_digest" '. + [{target:"client",id:$id,digest:$digest}]' <<< "$artifacts")"
fi
jq -c -n --arg module "$module_id" --arg version "$version" --argjson artifacts "$artifacts" --argjson contracts "$contracts" \
  '{schemaVersion:1,module:{id:$module,version:$version,bundleDigest:"sha256:0000000000000000000000000000000000000000000000000000000000000000"},resolvedAt:"2026-01-01T00:00:00.0000000+00:00",runtimeVersion:$version,dependencies:[],artifacts:$artifacts,contracts:$contracts}' \
  | sed 's/+00:00/\\u002B00:00/' | tr -d '\n' > "$stage/manifest/module.lock.json"

sbom_template="$(find "$stage/sbom" -type f -name '*.spdx.json' -print -quit)"
bash "$repository/packaging/generate-sbom.sh" "$repository" "$sbom_template" "$stage/sbom/release.spdx.json" "$module_id" "$version" "$target_os-$target_arch"
find "$stage/sbom" -type f ! -name release.spdx.json -delete
lower_revision="$(printf '%s' "$revision" | tr '[:upper:]' '[:lower:]')"
jq --arg version "$version" --arg revision "$lower_revision" --arg target "$target_os-$target_arch" '.version=$version | .sourceRevision=$revision | .target=$target' "$stage/provenance/build.json" > "$stage/provenance/release.json"
mv "$stage/provenance/release.json" "$stage/provenance/build.json"

hashes="$(mktemp)"
find "$stage" -type f ! -path "$stage/manifest/file-hashes.json" ! -path "$stage/signature/*" -print0 |
  sort -z |
  while IFS= read -r -d '' file; do
    relative="${file#"$stage/"}"
    printf '%s\tsha256:%s\n' "$relative" "$(sha256sum "$file" | cut -d' ' -f1)"
  done > "$hashes"
canonical="$(mktemp)"
{
  printf 'murchalka-bundle-v1\n'
  while IFS=$'\t' read -r path digest; do printf '%s\n%s\n' "$path" "$digest"; done < "$hashes"
} > "$canonical"
bundle_digest="sha256:$(sha256sum "$canonical" | cut -d' ' -f1)"
jq -c --arg digest "$bundle_digest" '.module.bundleDigest=$digest' "$stage/manifest/module.lock.json" > "$stage/manifest/module.lock.release.json"
mv "$stage/manifest/module.lock.release.json" "$stage/manifest/module.lock.json"
jq -Rn '[inputs | split("\t") | {(.[0]): .[1]}] | add | {schemaVersion:1,algorithm:"sha256",files:.}' < "$hashes" > "$stage/manifest/file-hashes.json"
signature="$(openssl dgst -sha256 -sign "$key" "$canonical" | base64 | tr -d '\n')"
jq -n --arg keyId "$key_id" --arg signature "$signature" '{schemaVersion:1,publisher:"dev.murchalka",keyId:$keyId,algorithm:"ecdsa-p256-sha256",signature:$signature}' > "$stage/signature/signature.json"

find "$stage" -exec touch -t 202601010000 {} +
rm -f -- "$output"
(cd "$stage" && find . -type f -print | LC_ALL=C sort | zip -X -q "$output" -@)
[[ -s "$output" ]]
echo "$bundle_digest"
