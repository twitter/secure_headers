# frozen_string_literal: true
module SecureHeaders
  module DynamicConfig
    def self.included(base)
      base.extend(ClassMethods)
    end

    module ClassMethods
      def from_self(instance)
        new_instance = new
        new_instance.base_uri = instance.base_uri
        new_instance.block_all_mixed_content = instance.block_all_mixed_content
        new_instance.child_src = instance.child_src.dup
        new_instance.connect_src = instance.connect_src.dup
        new_instance.default_src = instance.default_src.dup
        new_instance.font_src = instance.font_src.dup
        new_instance.form_action = instance.form_action.dup
        new_instance.frame_ancestors = instance.frame_ancestors.dup
        new_instance.frame_src = instance.frame_src.dup
        new_instance.img_src = instance.img_src.dup
        new_instance.manifest_src = instance.manifest_src.dup
        new_instance.media_src = instance.media_src.dup
        new_instance.navigate_to = instance.navigate_to.dup
        new_instance.object_src = instance.object_src.dup
        new_instance.plugin_types = instance.plugin_types
        new_instance.prefetch_src = instance.prefetch_src.dup
        new_instance.preserve_schemes = instance.preserve_schemes
        new_instance.report_only = instance.report_only
        new_instance.report_uri = instance.report_uri.dup
        new_instance.require_sri_for = instance.require_sri_for
        new_instance.sandbox = instance.sandbox
        new_instance.script_nonce = instance.script_nonce
        new_instance.script_src = instance.script_src.dup
        new_instance.style_nonce = instance.style_nonce
        new_instance.style_src = instance.style_src.dup
        new_instance.worker_src = instance.worker_src.dup
        new_instance.upgrade_insecure_requests = instance.upgrade_insecure_requests
        new_instance.disable_nonce_backwards_compatibility = instance.disable_nonce_backwards_compatibility
        new_instance.disable_minification = instance.disable_minification
        new_instance
      end
    end

    def initialize(hash = nil)
      @base_uri = nil
      @block_all_mixed_content = nil
      @child_src = nil
      @connect_src = nil
      @default_src = nil
      @font_src = nil
      @form_action = nil
      @frame_ancestors = nil
      @frame_src = nil
      @img_src = nil
      @manifest_src = nil
      @media_src = nil
      @navigate_to = nil
      @object_src = nil
      @plugin_types = nil
      @prefetch_src = nil
      @preserve_schemes = nil
      @report_only = nil
      @report_uri = nil
      @require_sri_for = nil
      @sandbox = nil
      @script_nonce = nil
      @script_src = nil
      @style_nonce = nil
      @style_src = nil
      @worker_src = nil
      @upgrade_insecure_requests = nil
      @disable_nonce_backwards_compatibility = nil
      @disable_minification = nil

      from_hash(hash) if hash
    end

    def update_directive(directive, value)
      write_attribute(directive, value)
    end

    def directive_value(directive)
      case directive
      when :base_uri
        @base_uri
      when :block_all_mixed_content
        @block_all_mixed_content
      when :child_src
        @child_src
      when :connect_src
        @connect_src
      when :default_src
        @default_src
      when :font_src
        @font_src
      when :form_action
        @form_action
      when :frame_ancestors
        @frame_ancestors
      when :frame_src
        @frame_src
      when :img_src
        @img_src
      when :manifest_src
        @manifest_src
      when :media_src
        @media_src
      when :navigate_to
        @navigate_to
      when :object_src
        @object_src
      when :plugin_types
        @plugin_types
      when :prefetch_src
        @prefetch_src
      when :preserve_schemes
        @preserve_schemes
      when :report_only
        @report_only
      when :report_uri
        @report_uri
      when :require_sri_for
        @require_sri_for
      when :sandbox
        @sandbox
      when :script_nonce
        @script_nonce
      when :script_src
        @script_src
      when :style_nonce
        @style_nonce
      when :style_src
        @style_src
      when :worker_src
        @worker_src
      when :upgrade_insecure_requests
        @upgrade_insecure_requests
      when :disable_nonce_backwards_compatibility
        @disable_nonce_backwards_compatibility
      when :disable_minification
        @disable_minification
      else
        raise NoMethodError
      end
    end

    def merge(new_hash)
      new_config = self.class.from_self(self)
      new_config.send(:from_hash, new_hash)
      new_config
    end

    def merge!(new_hash)
      from_hash(new_hash)
    end

    def append(new_hash)
      from_hash(ContentSecurityPolicy.combine_policies(self.to_h, new_hash))
    end

    def to_h
      self.class::ATTRS.each_with_object({}) do |key, hash|
        value = directive_value(key)
        hash[key] = value unless value.nil?
      end
    end

    def opt_out?
      false
    end

    def ==(o)
      self.class == o.class && self.to_h == o.to_h
    end

    alias_method :[], :directive_value
    alias_method :[]=, :update_directive

    private
    def from_hash(hash)
      hash.each_pair do |k, v|
        next if v.nil?
        write_attribute(k, v)
      end
    end

    def write_attribute(attr, value)
      if PolicyManagement::DIRECTIVE_VALUE_TYPES[attr] == :source_list && value.is_a?(Enumerable)
        value = value.dup
      end

      case attr
      when :base_uri
        @base_uri = value
      when :block_all_mixed_content
        @block_all_mixed_content = value
      when :child_src
        @child_src = value
      when :connect_src
        @connect_src = value
      when :default_src
        @default_src = value
      when :font_src
        @font_src = value
      when :form_action
        @form_action = value
      when :frame_ancestors
        @frame_ancestors = value
      when :frame_src
        @frame_src = value
      when :img_src
        @img_src = value
      when :manifest_src
        @manifest_src = value
      when :media_src
        @media_src = value
      when :navigate_to
        @navigate_to = value
      when :object_src
        @object_src = value
      when :plugin_types
        @plugin_types = value
      when :prefetch_src
        @prefetch_src = value
      when :preserve_schemes
        @preserve_schemes = value
      when :report_only
        @report_only = value
      when :report_uri
        @report_uri = value
      when :require_sri_for
        @require_sri_for = value
      when :sandbox
        @sandbox = value
      when :script_nonce
        @script_nonce = value
      when :script_src
        @script_src = value
      when :style_nonce
        @style_nonce = value
      when :style_src
        @style_src = value
      when :worker_src
        @worker_src = value
      when :upgrade_insecure_requests
        @upgrade_insecure_requests = value
      when :disable_nonce_backwards_compatibility
        @disable_nonce_backwards_compatibility = value
      when :disable_minification
        @disable_minification = value
      else
        raise NoMethodError
      end
    end
  end

  class ContentSecurityPolicyConfigError < StandardError; end
  class ContentSecurityPolicyConfig

    HEADER_NAME = "Content-Security-Policy".freeze

    ATTRS = PolicyManagement::ALL_DIRECTIVES + PolicyManagement::META_CONFIGS + PolicyManagement::NONCES

    attr_accessor *ATTRS

    include DynamicConfig

    # based on what was suggested in https://github.com/rails/rails/pull/24961/files
    DEFAULT = {
      default_src: %w('self' https:),
      font_src: %w('self' https: data:),
      img_src: %w('self' https: data:),
      object_src: %w('none'),
      script_src: %w(https:),
      style_src: %w('self' https: 'unsafe-inline')
    }

    def report_only?
      false
    end

    def make_report_only
      ContentSecurityPolicyReportOnlyConfig.from_self(self).tap do |config|
        config.report_only = true
      end
    end
  end

  class ContentSecurityPolicyReportOnlyConfig < ContentSecurityPolicyConfig
    HEADER_NAME = "Content-Security-Policy-Report-Only".freeze

    def report_only?
      true
    end

    def make_report_only
      self
    end
  end
end
