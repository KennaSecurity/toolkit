# frozen_string_literal: true

source "https://rubygems.org"

# git_source(:github) do |repo_name|
#  repo_name = "#{repo_name}/#{repo_name}" unless repo_name.include?("/")
#  "https://github.com/#{repo_name}.git"
# end

# Only required for file upload types (Guardium and Qualys to Kenna Direct), comment out if unneeded:
# gem 'nokogiri'

gem "aws-sdk-guardduty"
gem "aws-sdk-inspector"
gem "json"
gem "rest-client"
gem "tty-pager"
gem "json-write-stream"

group :development, :test do
  gem "pry"
  gem "rspec"
  gem "rubocop", "~> 0.82.0", require: false
  gem "rubocop-github"
  gem "rubocop-performance", require: false
  gem "rubocop-rails", require: false
  gem "solargraph"
end
