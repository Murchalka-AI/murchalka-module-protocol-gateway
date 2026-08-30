#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 6 ]]; then
  echo "Usage: generate-sbom.sh <repository> <template> <output> <module-id> <version> <target>" >&2
  exit 2
fi

repository="$(cd "$1" && pwd)"
template="$2"
output="$3"
module_id="$4"
version="$5"
target="$6"
assets="$(find "$repository/src" -path '*/obj/project.assets.json' -type f -print -quit)"
[[ -n "$assets" && -f "$template" ]]

jq --arg module "$module_id" --arg version "$version" --arg target "$target" --slurpfile assets "$assets" '
  def spdx_id: gsub("[^A-Za-z0-9.-]"; "-");
  .packages[0] as $root
  | ($assets[0].libraries
      | to_entries
      | map(select(.value.type == "package"))
      | map(.key | capture("^(?<name>.+)/(?<version>[^/]+)$"))
      | unique_by(.name + "/" + .version)
      | sort_by(.name, .version)
      | map({
          name: .name,
          SPDXID: ("SPDXRef-Dependency-" + ((.name + "-" + .version) | spdx_id)),
          versionInfo: .version,
          downloadLocation: "NOASSERTION",
          filesAnalyzed: false,
          licenseConcluded: "NOASSERTION",
          licenseDeclared: "NOASSERTION",
          copyrightText: "NOASSERTION",
          externalRefs: [{
            referenceCategory: "PACKAGE-MANAGER",
            referenceType: "purl",
            referenceLocator: ("pkg:nuget/" + (.name | @uri) + "@" + .version)
          }]
        })) as $dependencies
  | ($root | .versionInfo = $version | .name = ($module + "-" + $version)) as $release
  | .name = ($module + "-" + $version + "-" + $target)
  | .documentNamespace = ("https://murchalka.dev/sbom/" + ($module | @uri) + "/" + $version + "/" + $target)
  | .packages = [$release] + $dependencies
  | .relationships = [
      {spdxElementId:"SPDXRef-DOCUMENT", relationshipType:"DESCRIBES", relatedSpdxElement:$release.SPDXID}
    ] + ($dependencies | map({
      spdxElementId:$release.SPDXID,
      relationshipType:"DEPENDS_ON",
      relatedSpdxElement:.SPDXID
    }))
' "$template" > "$output"
