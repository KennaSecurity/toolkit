module Kenna 
  module Toolkit
  class Generator < Kenna::Toolkit::BaseTask
  
    def self.metadata
      {
        id: "generator",
        name: "Generator (of demo data)",
        description: "This task generates some simple demo data!",
        disabled: true,
        options: [
          { 
            :name => "example_option", 
            :type => "string", 
            :required => false, 
            :default => "just an example", 
            :description => "This is an example option. Set it to whatever you want and we'll print it" 
          }
        ]
      }
    end
  
    def run(options)
      super
  
      print_good "This is an example task!"
      print_good ""
      print_good "Running the example task with the following options:\n#{@options}"
  
      # do things here 
  
      print_error "Just an example error! Not to worry!"
  
      print_good "Input:\n#{`ls -latr /opt/toolkit/input`}"
      print_good "Output:\n#{`ls -latr /opt/toolkit/output`}"
    end
    
  end
  end
  end