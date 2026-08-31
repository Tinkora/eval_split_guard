#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "open3"
require "tempfile"

ROOT = File.expand_path("..", __dir__)
NORMALIZER = File.join(ROOT, "scripts", "normalize_cyclonedx_sbom.rb")

fixture = {
  "bomFormat" => "CycloneDX",
  "specVersion" => "1.3",
  "metadata" => {
    "component" => {
      "type" => "application",
      "bom-ref" => "path+file:///home/runner/work/eval_split_guard/eval_split_guard#0.1.0-alpha.2",
      "name" => "eval_split_guard",
      "version" => "0.1.0-alpha.2",
      "purl" => "pkg:cargo/eval_split_guard@0.1.0-alpha.2?download_url=file://.",
      "components" => [
        {
          "type" => "library",
          "bom-ref" => "path+file:///home/runner/work/eval_split_guard/eval_split_guard#0.1.0-alpha.2 target-0",
          "name" => "eval_split_guard",
          "version" => "0.1.0-alpha.2",
          "purl" => "pkg:cargo/eval_split_guard@0.1.0-alpha.2?download_url=file://.#src/lib.rs"
        },
        {
          "type" => "application",
          "bom-ref" => "path+file:///home/runner/work/eval_split_guard/eval_split_guard#0.1.0-alpha.2 target-1",
          "name" => "eval_split_guard",
          "version" => "0.1.0-alpha.2",
          "purl" => "pkg:cargo/eval_split_guard@0.1.0-alpha.2?download_url=file://.#src/main.rs"
        }
      ]
    }
  },
  "components" => [
    {
      "type" => "library",
      "bom-ref" => "registry+https://github.com/rust-lang/crates.io-index#anyhow@1.0.104",
      "name" => "anyhow",
      "version" => "1.0.104",
      "purl" => "pkg:cargo/anyhow@1.0.104"
    }
  ],
  "dependencies" => [
    {
      "ref" => "path+file:///home/runner/work/eval_split_guard/eval_split_guard#0.1.0-alpha.2",
      "dependsOn" => ["registry+https://github.com/rust-lang/crates.io-index#anyhow@1.0.104"]
    },
    {
      "ref" => "registry+https://github.com/rust-lang/crates.io-index#anyhow@1.0.104",
      "dependsOn" => []
    }
  ]
}

Tempfile.create(["sbom", ".cdx.json"]) do |file|
  file.write(JSON.pretty_generate(fixture))
  file.close

  stdout, stderr, status = Open3.capture3("ruby", NORMALIZER, file.path)
  abort("normalizer failed: #{stdout}#{stderr}") unless status.success?

  normalized_text = File.read(file.path, encoding: "UTF-8")
  abort("normalized SBOM contains a local file URI") if normalized_text.match?(%r{(?:path\+)?file://})
  abort("normalized SBOM contains a runner path") if normalized_text.include?("/home/runner/")

  normalized = JSON.parse(normalized_text)
  root = normalized.fetch("metadata").fetch("component")
  root_ref = "pkg:cargo/eval_split_guard@0.1.0-alpha.2"
  abort("root bom-ref is not canonical") unless root.fetch("bom-ref") == root_ref
  abort("root purl is not canonical") unless root.fetch("purl") == root_ref

  target_refs = root.fetch("components").map { |component| component.fetch("bom-ref") }
  expected_targets = ["#{root_ref}#src/lib.rs", "#{root_ref}#src/main.rs"]
  abort("target bom-refs are not stable") unless target_refs == expected_targets
  abort("target purls do not match bom-refs") unless root.fetch("components").map { |component| component.fetch("purl") } == expected_targets

  dependencies = normalized.fetch("dependencies")
  abort("root dependency ref was not rewritten") unless dependencies.first.fetch("ref") == root_ref

  component_refs = [root.fetch("bom-ref")] + target_refs + normalized.fetch("components").map { |component| component.fetch("bom-ref") }
  dependency_refs = dependencies.flat_map { |dependency| [dependency.fetch("ref"), *dependency.fetch("dependsOn", [])] }
  abort("normalized SBOM has duplicate component refs") unless component_refs.uniq.length == component_refs.length
  abort("normalized SBOM has dangling dependency refs") unless (dependency_refs - component_refs).empty?
end

puts "CycloneDX SBOM normalization contract passed"
