# frozen_string_literal: true

# require task-specific libraries etc

require "date"
require "base64"
require "ostruct"
require "tty-pager"

module Kenna
  module Toolkit
    class BaseTask
      include Kenna::Toolkit::Helpers
      include Kenna::Toolkit::KdiHelpers

      def self.inherited(base)
        Kenna::Toolkit::TaskManager.register(base)
      end

      # YourTask#new takes the same options as #run so you can separate the concerns of configuring
      # and running the task.
      def initialize(opts = nil)
        require_options(opts) if opts
      end

      # A task can pass commandline options upon initialization or at run time.
      # If at run time, the task's run method should call super
      def run(opts = nil)
        require_options(opts) unless opts.nil? && @options

        print_good ""
        print_good "Launching the #{self.class.metadata[:name]} task!"
        print_good "Toolkit running hosted" if running_hosted?
        print_good ""
      end

      def self.initialize_options(opts)
        metadata[:options].each do |opt|
          opt_name = opt[:name].to_sym
          opt_default = opt[:default]
          opt_input_value = opts[opt_name]

          # Set default arguments
          print_good "Setting #{opt_name} to default value: #{opt_default}" unless opt_default.blank?
          opts[opt_name] = opt_default unless opt_input_value
          # set empty string to nil so it's a little easier to check for that
          opts[opt_name] = nil if opts[opt_name].blank?
          opt_value = opts[opt_name]

          next unless opt_value

          # Convert arguments to ruby types based on their type here
          case opt[:type]
          when "boolean"
            converted_value = opt_value.to_s == "true"
            print_good "Converting #{opt_name} with input value #{opt_input_value} to #{converted_value}." unless opt_input_value.to_s == converted_value.to_s
            opts[opt_name] = converted_value
          when "integer"
            # Integer values <= 0 are considered nil by definition.
            # Additionally, if an integer input value is 0 (converts to nil), then it should convert to its default value if present.
            converted_value = (opt_value.to_i if opt_value.to_i.positive?) || (opt_default.to_i if opt_default.to_i.positive?)
            print_good "Converting #{opt_name} with input value #{opt_input_value.inspect} to #{converted_value.inspect}." unless opt_input_value.to_s == converted_value.to_s
            opts[opt_name] = converted_value
          when "array"
            converted_value = opt_value.is_a?(Array) ? opt_value : (opt_value || "").split(",").map(&:strip)
            print_good "Converting #{opt_name} with input value #{opt_input_value} to #{converted_value.inspect}."
            opts[opt_name] = converted_value
          end
        end
        opts
      end

      def require_options(opts)
        # Set global debug. You can get its value calling debug? method globally
        $toolkit_debug = opts[:debug] == "true"
        $toolkit_running_local = !running_hosted?

        # pull our required arguments out
        required_options = self.class.metadata[:options].select { |a| a[:required] }

        # colllect all the missing arguments
        missing_options = []
        required_options.each do |req|
          missing = true
          opts.each do |name, _value|
            missing = false if (req[:name]).to_s.strip == name.to_s.strip
          end
          missing_options << req if missing
        end

        # Task help!
        if opts[:help]
          print_task_help self.class.metadata[:id]
          print_good "Returning!"
          exit
        end

        # Task readme!
        if opts[:readme]
          print_readme self.class.metadata[:id]
          print_good "Returning!"
          exit
        end

        # if we do have missing ones, lets warn the user here and return
        unless missing_options.empty?
          missing_options.each do |arg|
            print_error "Missing! #{arg[:name]}: #{arg[:description]}"
          end
          fail_task "Required options missing. Cowardly refusing to continue!"
        end

        # Initialize default values and perform string to Object conversions
        @options = self.class.initialize_options(opts)

        # Save Task Name as a class variable for sending with API call in Client
        Kenna::Api::Client.task_name = opts[:task]

        # Print out the options so the user knows and logs what we're doing
        @options.each do |k, v|
          if k =~ /key/ ||  k =~ /token/ || k =~ /secret/ || k =~ /_id/ || k =~ /password/ # special case anything that has key in it
            print_good "Got option: #{k}: #{v.to_s[0]}*******#{v.to_s[-3..-1]}" if v
          else
            print_good "Got option: #{k}: #{v}"
          end
        end
      end

      def options
        OpenStruct.new(@options)
      end

      private

      def running_hosted?
        @running_hosted ||= aws_host_info.present?
      end

      def aws_host_info
        RestClient::Request.execute(
          method: :get,
          url: "http://169.254.169.254/latest/metadata/",
          timeout: 1
        )
      rescue StandardError
        nil
      end
    end
  end
end
