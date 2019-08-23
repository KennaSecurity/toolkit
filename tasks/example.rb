module Kenna 
module Toolkit
class Example < Kenna::Toolkit::BaseTask

  def metadata 
    {
      id: "example",
      name: "Example Task",
      description: "This task is simply an example!",
      options: [
        { 
          :name => "example_option", 
          :type => "string", 
          :required => true, 
          :default => "just an example", 
          :description => "This is an example option. Set it to whatever you want and we'll print it" 
        }
      ]
    }
  end

  def run(options)
    super

    print_good "Running the example task with the following options:\n#{@options}"
  end

end
end
end