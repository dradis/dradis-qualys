module Dradis::Plugins::Qualys
  class Engine < ::Rails::Engine
    isolate_namespace Dradis::Plugins::Qualys

    include ::Dradis::Plugins::Base
    description 'Processes Qualys output'
    provides :upload

    initializer 'qualys.importmap', before: 'importmap' do |app|
      app.config.importmap.draw(root.join('config/importmap.rb'))
    end

    # Because this plugin provides two export modules, we have to overwrite
    # the default .uploaders() method.
    #
    # See:
    #  Dradis::Plugins::Upload::Base in dradis-plugins
    def self.upload_detectors
      [
        'dradis/plugins/qualys/upload_detectors/asset',
        'dradis/plugins/qualys/upload_detectors/vuln',
        'dradis/plugins/qualys/upload_detectors/was'
      ]
    end

    def self.uploaders
      [
        Dradis::Plugins::Qualys::Asset,
        Dradis::Plugins::Qualys::Vuln,
        Dradis::Plugins::Qualys::WAS
      ]
    end
  end
end
