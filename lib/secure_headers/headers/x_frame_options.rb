module SecureHeaders
  class XFOBuildError < StandardError; end
  class XFrameOptions < Header
    module Constants
      XFO_HEADER_NAME = "X-Frame-Options"

      VALID_XFO_HEADER = /\A(SAMEORIGIN\z|DENY\z|ALLOW-FROM[:\s])/i
      CONFIG_KEY = :x_frame_options
      SAMEOROGIN = "SAMEORIGIN"
      DENY = "DENY"
      ALLOW_FROM = "ALLOW-FROM"
      DEFAULT_VALUE = SAMEOROGIN
    end
    include Constants

    def initialize(config = nil)
      @config = config
    end

    def name
      XFO_HEADER_NAME
    end

    def value
      case @config
      when NilClass
        DEFAULT_VALUE
      when String
        @config
      else
        @config[:value]
      end
    end

    def self.validate_config(config)
      return if config.nil?
      value = config.is_a?(Hash) ? config[:value] : config
      unless value =~ VALID_XFO_HEADER
        raise XFOBuildError.new("Value must be SAMEORIGIN|DENY|ALLOW-FROM:")
      end
    end
  end
end
