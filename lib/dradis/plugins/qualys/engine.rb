module Dradis::Plugins::Qualys
  class Engine < ::Rails::Engine
    isolate_namespace Dradis::Plugins::Qualys

    include ::Dradis::Plugins::Base
    description 'Processes Qualys output'
    provides :upload
  end
end

