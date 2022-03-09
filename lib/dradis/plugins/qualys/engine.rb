module Dradis::Plugins::Qualys
  class Engine < ::Rails::Engine
    isolate_namespace Dradis::Plugins::Qualys

    include ::Dradis::Plugins::Base
    description 'Processes Qualys output'
    provides :upload

    # Because this plugin provides two export modules, we have to overwrite
    # the default .uploaders() method.
    #
    # See:
    #  Dradis::Plugins::Upload::Base in dradis-plugins
    def self.uploaders
      [
        Dradis::Plugins::Qualys::Asset,
        Dradis::Plugins::Qualys::Vuln,
        Dradis::Plugins::Qualys::WAS
      ]
    end
  end
end
