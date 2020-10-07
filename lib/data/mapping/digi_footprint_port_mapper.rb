module Kenna
  module Toolkit
  module Data
  module Mapping
  class DigiFootprintPortMapper
  
    # returns 0-100 depending on the severity of the 
    def self.get_canonical_port_severity_score(port_num)
      case port_num
      when 80, 443, 8080
        score = 10
      else
        score = 60
      end
    score
    end


  end
end
end
end
end  