#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

root = File.expand_path("..", __dir__)
path = File.join(root, ".github/workflows/release.yml")
workflow = File.read(path, encoding: "UTF-8")

YAML.safe_load(workflow, aliases: true)

required_fragments = [
  "ruby scripts/test_release_workflow.rb",
  "ruby scripts/test_normalize_cyclonedx_sbom.rb",
  "ruby scripts/normalize_cyclonedx_sbom.rb eval_split_guard.cdx.json",
  'predicate-type: "https://tinkora.dev/attestations/release-evidence/v1"',
  'git cat-file -t "refs/tags/${GITHUB_REF_NAME}"',
  '[[ "${tag_type}" == "tag" ]]',
  'expected_assets=(',
  'unexpected release asset inventory',
  'gh release create "$GITHUB_REF_NAME"',
  'select(.tag_name == env.GITHUB_REF_NAME and .draft == true)',
  'releases/assets/${asset_id}',
  'if [[ "${GITHUB_REF_NAME}" == *-* ]]',
  'release_args+=(--prerelease)',
  'sha256sum --check --strict SHA256SUMS',
  'released-assets',
  'resolve_draft_release_id()',
  'delete_release_with_retry()',
  'for attempt in {1..6}',
  'matching_count="${#matching_ids[@]}"',
  'multiple matching drafts found for ${GITHUB_REF_NAME}',
  'draft did not become visible after bounded retries',
  'failed to delete draft release ${candidate_id} after bounded retries'
]

required_fragments.each do |fragment|
  abort("release workflow is missing #{fragment.inspect}") unless workflow.include?(fragment)
end

action_references = workflow.scan(/^\s*uses:\s*([^@\s]+)@([^\s#]+)/).map do |name, revision|
  [name, revision]
end
unpinned = action_references.reject { |_name, revision| revision.match?(/\A[0-9a-f]{40}\z/) }
abort("release workflow has unpinned actions: #{unpinned.map(&:first).join(', ')}") unless unpinned.empty?

abort("stable releases must not always be prereleases") if workflow.match?(/gh release create[^\n]*--prerelease/)
abort("draft releases cannot be resolved through the tag endpoint") if workflow.include?("releases/tags/${GITHUB_REF_NAME}")
abort("gh release download cannot resolve draft releases") if workflow.include?('gh release download "$GITHUB_REF_NAME"')

resolve_body = workflow[/resolve_draft_release_id\(\) \{(?<body>.*?)^          \}/m, :body]
abort("release workflow is missing the draft resolver body") unless resolve_body
abort("draft resolver must retry zero matches") unless resolve_body.include?('[[ "${matching_count}" -eq 0 ]]')
abort("draft resolver must return exactly one match") unless resolve_body.include?('[[ "${matching_count}" -eq 1 ]]')
abort("draft resolver must fail closed on multiple matches") unless resolve_body.include?('return 1')

cleanup_body = workflow[/cleanup\(\) \{(?<body>.*?)^          \}/m, :body]
abort("release workflow is missing the cleanup body") unless cleanup_body
abort("cleanup must use bounded draft resolution") unless cleanup_body.include?('resolve_draft_release_id')
abort("cleanup must use bounded deletion retries") unless cleanup_body.include?('delete_release_with_retry')

puts "release workflow contract passed"
