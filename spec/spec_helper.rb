require 'rubygems'
require 'bundler/setup'
require 'nokogiri'

require 'combustion'

Dir[Rails.root.join('spec/support/**/*.rb')].each { |f| require f }

Combustion.initialize!

RSpec.configure do |config|
  config.include SpecMacros
end
