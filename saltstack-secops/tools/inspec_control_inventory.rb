#!/usr/bin/env ruby
# frozen_string_literal: true

require 'csv'
require 'json'
require 'optparse'
require 'pathname'

OPTIONS = {
  format: 'jsonl',
  include_text: false,
  limit: nil,
  root: Pathname.pwd
}.freeze

def parse_options
  options = OPTIONS.dup

  OptionParser.new do |parser|
    parser.banner = 'Usage: ruby saltstack-secops/tools/inspec_control_inventory.rb [path] [options]'

    parser.on('--format FORMAT', 'Output format: jsonl, json, csv') do |value|
      options[:format] = value
    end

    parser.on('--include-text', 'Include full check and fix text') do
      options[:include_text] = true
    end

    parser.on('--limit N', Integer, 'Limit records emitted') do |value|
      options[:limit] = value
    end

    parser.on('-h', '--help', 'Show this help') do
      puts parser
      exit
    end
  end.parse!

  options[:scope] = Pathname(ARGV.shift || '.').expand_path
  options
end

def clean_text(value)
  return nil if value.nil?

  value
    .gsub(/\\(["'])/, '\1')
    .gsub(/\r\n?/, "\n")
    .lines
    .map(&:rstrip)
    .join("\n")
    .strip
end

def capture_quoted(body, keyword)
  match = body.match(/^\s*#{Regexp.escape(keyword)}\s+(['"])(.*?)\1/m)
  clean_text(match&.[](2))
end

def capture_desc(body, label)
  match = body.match(/^\s*desc\s+['"]#{Regexp.escape(label)}['"]\s*,\s*(['"])(.*?)\1/m)
  clean_text(match&.[](2))
end

def parse_tag_value(raw_value)
  raw = raw_value.strip.sub(/\s+#.*$/, '')

  return raw.scan(/['"]([^'"]+)['"]/).flatten if raw.start_with?('[')

  quoted = raw.match(/\A(['"])(.*?)\1\z/m)
  return clean_text(quoted[2]) if quoted

  raw
end

def extract_tags(body)
  tags = {}

  body.scan(/^\s*tag\s+([a-zA-Z0-9_]+):\s*(.+)$/) do |name, raw_value|
    tags[name] = parse_tag_value(raw_value)
  end

  tags
end

def find_profile_path(path)
  path.ascend do |candidate|
    return candidate if candidate.join('inspec.yml').file?
  end

  nil
end

def relative_path(path, root)
  path.relative_path_from(root).to_s
rescue ArgumentError
  path.to_s
end

def component_name(profile_path)
  return nil unless profile_path

  profile_path.parent.join('inspec.yml').file? ? profile_path.basename.to_s : nil
end

def inventory_record(path, root, include_text:)
  body = path.read
  control_id = body.match(/^\s*control\s+['"]([^'"]+)['"]\s+do/)&.[](1)
  return nil unless control_id

  tags = extract_tags(body)
  profile_path = find_profile_path(path.dirname)

  record = {
    source_path: relative_path(path, root),
    profile_path: profile_path ? relative_path(profile_path, root) : nil,
    component: component_name(profile_path),
    control_id: control_id,
    title: capture_quoted(body, 'title'),
    impact: body.match(/^\s*impact\s+([0-9.]+)/)&.[](1),
    severity: tags['severity'],
    gid: tags['gid'],
    rid: tags['rid'],
    stig_id: tags['stig_id'],
    gtitle: tags['gtitle'],
    satisfies: tags['satisfies'],
    cci: tags['cci'],
    nist: tags['nist'],
    has_check: !capture_desc(body, 'check').nil?,
    has_fix: !capture_desc(body, 'fix').nil?
  }

  if include_text
    record[:check] = capture_desc(body, 'check')
    record[:fix] = capture_desc(body, 'fix')
  end

  record
end

def control_files(scope)
  if scope.file?
    [scope]
  else
    scope.glob('**/controls/*.rb').sort
  end
end

def emit(records, format)
  case format
  when 'jsonl'
    records.each { |record| puts JSON.generate(record) }
  when 'json'
    puts JSON.pretty_generate(records)
  when 'csv'
    headers = records.flat_map(&:keys).uniq
    puts CSV.generate_line(headers)
    records.each do |record|
      puts CSV.generate_line(headers.map { |header| record[header].is_a?(Array) ? record[header].join('|') : record[header] })
    end
  else
    warn "Unsupported format: #{format}"
    exit 1
  end
end

options = parse_options
root = Pathname.pwd

records = control_files(options[:scope]).map do |path|
  inventory_record(path.expand_path, root, include_text: options[:include_text])
end.compact

records = records.first(options[:limit]) if options[:limit]

emit(records, options[:format])
