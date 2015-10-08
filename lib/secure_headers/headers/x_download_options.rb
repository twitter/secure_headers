module SecureHeaders
  class XDOBuildError < StandardError; end
  class XDownloadOptions < Header
    module Constants
      XDO_HEADER_NAME = "X-Download-Options"
      DEFAULT_VALUE = 'noopen'
      CONFIG_KEY = :x_download_options
    end
    include Constants

    def initialize(config = nil)
      @config = config
    end

    def name
      XDO_HEADER_NAME
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
      unless value.casecmp(DEFAULT_VALUE) == 0
        raise XDOBuildError.new("Value can only be nil or 'noopen'")
      end
    end
  end
end
