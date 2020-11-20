class String
  def sanitize_unicode
    encode("UTF-8", {
             undef: :replace,
             invalid: :replace,
             replace: "?"
           }).gsub("\u0000", "")
  end

  def to_string_identifier
    gsub!(".", "_")
    gsub!("~", "_")
    gsub!("/", "_")
    gsub!("\\", "_")
    gsub!("+", "_")
    gsub!("-", "_")
    downcase
  end
end
