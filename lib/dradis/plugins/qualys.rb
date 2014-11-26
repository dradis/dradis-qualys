module Dradis
  module Plugins
    module Qualys
      # This is required while we transition the Upload Manager to use
      # Dradis::Plugins only
      module Meta
        NAME = "Qualys XML upload plugin"
        EXPECTS = "Qualys XML format."
        module VERSION
          include Dradis::Plugins::Qualys::VERSION
        end
      end
    end
  end
end

require 'dradis/plugins/qualys/engine'
require 'dradis/plugins/qualys/field_processor'
require 'dradis/plugins/qualys/importer'
require 'dradis/plugins/qualys/version'
