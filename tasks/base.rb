module Kenna
module Toolkit
class BaseTask
  include Kenna::Toolkit::Helpers

  # all tasks must implement a run method and call super, so 
  # this code should be run immediately upon entry into the task
  def run(opts)

    # pull our required arguments out 
    required_options = metadata[:options].select{|a| a[:required]}

    # colllect all the missing arguments
    missing_options = []
    required_options.each do |req|
      missing = true
      opts.each do |name, value|
        missing = false if "#{req[:name]}".strip == "#{name}".strip
      end
      missing_options << req if missing
    end

    # if we do have missing ones, lets warn the user here and return
    unless missing_options.empty?
      print_error "Required Options Missing, Cannot Continue!"
      missing_options.each do |arg|
        print_error "Missing! #{arg[:name]}: #{arg[:description]}"
      end
      exit
    end

    # !!!!!!!
    # TODO !! - validate arguments based on their type here
    # !!!!!!!

    # if we made it here, we have the right arguments!
    @options = opts

    # Print out the options so the user knows and logs what we're doing
    @options.each do |k,v| 
      if k =~ /key/ ||  k =~ /token/ # special case anything that has key in it
        print_good "Got option: #{k}: ********#{v[-4..-1]}"
      else 
        print_good "Got option: #{k}: #{v}"
      end
    end

    print_good ""
    print_good "Launching the #{metadata[:name]} task!"
    print_good "" 
  end

end
end
end
