#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

root = File.expand_path("..", __dir__)
path = File.join(root, ".github/workflows/release.yml")
workflow = File.read(path, encoding: "UTF-8")

YAML.safe_load(workflow, aliases: true)

required_fragments = [
  "ruby scripts/test_release_workflow.rb",
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
  'released-assets'
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

puts "release workflow contract passed"
