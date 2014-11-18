require 'rubygems'
require 'bundler/setup'

require 'combustion'

Combustion.initialize!

require 'rspec/rails'

RSpec.configure do |config|
  # Filter which specs to run
  config.filter_run :focus => true
  config.run_all_when_everything_filtered = true
  # Enable colors
  config.color_enabled = true
  # Use the specified formatter
  config.formatter = :documentation

  # If you're not using ActiveRecord, or you'd prefer not to run each of your
  # examples within a transaction, remove the following line or assign false
  # instead of true.
  config.use_transactional_fixtures = false

  config.before(:suite) do
    DatabaseCleaner.strategy = :transaction
    DatabaseCleaner.clean_with(:truncation)
  end

  config.before(:each) do
    DatabaseCleaner.start
  end

  config.after(:each) do
    DatabaseCleaner.clean
  end
end