module Kenna 
module Toolkit
class FootprintParser < Kenna::Toolkit::BaseTask

  def metadata 
    {
      id: "footprint_parser",
      name: "Footprint Parser",
      description: "This task parses digital footprinting data from CSV files",
      options: [
        {:name => "kenna_api_token", 
          :type => "api_token", 
          :required => true, 
          :default => nil, 
          :description => "Kenna API Key" },
        {:name => "kenna_api_host", 
          :type => "hostname", 
          :required => false  , 
          :default => "api.kennasecurity.com", 
          :description => "Kenna API Hostname" },
        {:name => "input", 
          :type => "filename", 
          :required => false, 
          :default => "input/footprinting", 
          :description => "Path to footprinting data, relative to #{$basedir}"  }
      ]
    }
  end

  def run(options)
    super
  end

end
end
end