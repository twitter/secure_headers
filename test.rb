# frozen_string_literal: true

lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "secure_headers"

require "stackprof"
require "benchmark/ips"
require "rack"

request = Rack::Request.new("HTTP_X_FORWARDED_SSL" => "on")
::SecureHeaders::Configuration.default do |config|
  config.csp.merge!(disable_minification: true)
end

# ::SecureHeaders::Configuration.override(:disable_minification)

puts SecureHeaders.header_hash_for(request)

result = Benchmark.ips do |x|
  x.report "/status" do
    SecureHeaders.header_hash_for(request)
  end
end

output = "stackprof-status.dump"
puts output

StackProf.run(mode: :wall, out: output, raw: true) do
  result.entries[0].iterations.times do
    SecureHeaders.header_hash_for(request)
  end
end
system "stackprof #{output}"
