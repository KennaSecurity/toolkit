class String
  def sanitize_unicode
    self.encode("UTF-8", { 
      :undef => :replace,
     :invalid => :replace,
     :replace => "?" }).gsub("\u0000","")
  end


  def to_string_identifier
    self.gsub!(".","_")
    self.gsub!("~","_")
    self.gsub!("/","_")
    self.gsub!("\\","_")
    self.gsub!("+","_")
    self.gsub!("-","_")
  self.downcase
  end

end