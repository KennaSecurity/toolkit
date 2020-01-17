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

      def self.find_by_id(provided_id)
        @tasks.select{|x| x.metadata.id == provided_id }
      end

    end
  end
end
