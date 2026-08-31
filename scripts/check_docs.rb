# frozen_string_literal: true

require "pathname"
require "uri"

ROOT = Pathname(__dir__).join("..").expand_path
PAIRS = [
  %w[README.md README.zh-CN.md],
  %w[CONTRIBUTING.md CONTRIBUTING.zh-CN.md],
  %w[SECURITY.md SECURITY.zh-CN.md],
  %w[SUPPORT.md SUPPORT.zh-CN.md],
  %w[CODE_OF_CONDUCT.md CODE_OF_CONDUCT.zh-CN.md],
  %w[docs/PRODUCT_SPEC.md docs/PRODUCT_SPEC.zh-CN.md]
].freeze

errors = []

PAIRS.each do |english, chinese|
  errors << "missing bilingual document: #{english}" unless ROOT.join(english).file?
  errors << "missing bilingual document: #{chinese}" unless ROOT.join(chinese).file?
end

ROOT.glob("**/*.md").sort.each do |document|
  relative_document = document.relative_path_from(ROOT)
  document.read(encoding: "UTF-8").scan(/\[[^\]]*\]\(([^)]+)\)/).flatten.each do |raw_target|
    target = raw_target.strip.sub(/\s+["'][^"']*["']\z/, "")
    next if target.empty? || target.start_with?("#", "mailto:")

    uri = URI.parse(target)
    next if uri.scheme || uri.host

    path = URI::DEFAULT_PARSER.unescape(target.split("#", 2).first)
    next if path.empty?

    resolved = document.dirname.join(path).cleanpath
    errors << "broken internal link in #{relative_document}: #{target}" unless resolved.exist?
  rescue URI::InvalidURIError
    errors << "invalid link in #{relative_document}: #{target}"
  end
end

abort(errors.join("\n")) unless errors.empty?

puts "Documentation contracts passed"
