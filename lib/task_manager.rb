module Kenna
  module Toolkit
    module TaskManager

      def self.register(klass)
        @tasks = [] unless @tasks
        @tasks << klass
      end

      def self.tasks
        @tasks
      end

    end
  end
end
