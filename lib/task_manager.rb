module Kenna
  module Toolkit
    module TaskManager
      def self.register(klass)
        @tasks ||= []
        @tasks << klass
      end

      def self.tasks
        @tasks.reject { |x| x.metadata[:disabled] }
      end

      def self.find_by_id(provided_id)
        @tasks.select { |x| x.metadata[:id] == provided_id }.first
      end
    end
  end
end
