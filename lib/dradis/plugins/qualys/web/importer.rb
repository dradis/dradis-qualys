module Dradis::Plugins::Qualys

  # This module knows how to parse Qualys Web Application Scanner format.
  module Web
    def self.meta
      package = Dradis::Plugins::Qualys

      {
        name: package::Engine::plugin_name,
        description: 'Upload Qualys WAS results (.xml)',
        version: package.version
      }
    end

    class Importer < Dradis::Plugins::Upload::Importer
      def initialize(args={})
        args[:plugin] = Dradis::Plugins::Qualys
        super(args)
      end

      def import(params={})
        file_content = File.read(params[:file])

        logger.info { 'Parsing Qualys WAS XML output file...'}
        doc = Nokogiri::XML(file_content)
        logger.info { 'Done.' }

        if doc.root.name != 'WAS_SCAN_REPORT'
          error = 'Document doesn\'t seem to be in the Qualys WAS XML format.'
          logger.fatal { error }
          content_service.create_note text: error
          return false
        end

        logger.info { 'Global Summary information'}

        xml_global_summary = doc.at_xpath('WAS_SCAN_REPORT/SUMMARY/GLOBAL_SUMMARY')
        logger.info { 'Security Risk: ' + xml_global_summary.at_xpath('./SECURITY_RISK').text }
        logger.info { 'Vulnerabilities found: ' + xml_global_summary.at_xpath('./VULNERABILITY').text }

        xml_webapp = doc.at_xpath('WAS_SCAN_REPORT/APPENDIX/WEBAPP')
        process_webapp(xml_webapp)

        doc.xpath('WAS_SCAN_REPORT/GLOSSARY/QID_LIST/QID').each do |xml_qid|
          process_issue(xml_qid)
        end

        true
      end

      private
      def process_issue(xml_qid)
        qid = xml_qid.at_xpath('QID').text
        logger.info{ "\t => Creating new issue (plugin_id: #{ qid })" }
        issue_text = template_service.process_template(template: 'was-issue', data: xml_qid)
        issue = content_service.create_issue(text: issue_text, id: qid)
      end

      def process_webapp(xml_webapp)

        id = xml_webapp.at_xpath('./ID').text
        name = xml_webapp.at_xpath('./NAME').text
        url = xml_webapp.at_xpath('./URL').text
        scope = xml_webapp.at_xpath('./SCOPE').text

        uri = URI(url)
        @node = content_service.create_node(label: uri.host)

        @node.set_property('qualys.webapp.id', id)
        @node.set_property('qualys.webapp.name', name)
        @node.set_property('qualys.webapp.url', url)
        @node.set_property('qualys.webapp.scope', scope)
        @node.save!

        logger.info { 'Webapp name: ' + name }
        logger.info { 'Webapp URL: ' + url }
        logger.info { 'Webapp scope: ' + scope }
      end
    end
  end
end
