require_relative '../../../spec/rspec_helper'
require 'rspec'

describe "Kenna" do
describe "Toolkit" do
describe "Expanse" do
describe "Client" do

  it "can authenticate" do
    puts "Using Key: #{ENV["EXPANSE_KEY"]}"
    c = Kenna::Toolkit::Expanse::Client.new "#{ENV["EXPANSE_KEY"]}"
    expect(c.successfully_authenticated?).to be true
  end

  it "can return a csv for a given exposure type" do 
    c = Kenna::Toolkit::Expanse::Client.new ENV["EXPANSE_KEY"]
    result = c.cloud_exposure_csv("ftp-servers")
    expect(result.first.include?("port")).to be true
  end

end
end
end
end