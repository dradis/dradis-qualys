module Dradis::Plugins::Qualys
  module Asset
    ROOT_PATH_NAME = 'ASSET_DATA_REPORT'.freeze
    def self.meta
      package = Dradis::Plugins::Qualys

      {
        name: package::Engine::plugin_name,
        description: 'Upload Qualys Asset results (.xml)',
        version: package.version
      }
    end

    class Importer < Dradis::Plugins::Upload::Importer
      def self.templates
        { evidence: 'asset-evidence', issue: 'asset-issue' }
      end

      def initialize(args={})
        args[:plugin] = Dradis::Plugins::Qualys
        super(args)

        @issue_lookup = {}
      end

      # The framework will call this function if the user selects this plugin from
      # the dropdown list and uploads a file.
      # @returns true if the operation was successful, false otherwise
      def import(params={})
        file_content = File.read( params[:file] )

        logger.info { 'Parsing Qualys ASSET XML output file...' }
        doc = Nokogiri::XML(file_content)
        logger.info { 'Done.' }

        if doc.root.name != ROOT_PATH_NAME
          error = 'No scan results were detected in the uploaded file. Ensure you uploaded a Qualys ASSET XML file.'
          logger.fatal { error }
          content_service.create_note text: error
          return false
        end

        doc.xpath('ASSET_DATA_REPORT/GLOSSARY/VULN_DETAILS_LIST/VULN_DETAILS').each do |xml_issue|
          process_issue(xml_issue)
        end

        doc.xpath('ASSET_DATA_REPORT/HOST_LIST/HOST').each do |xml_node|
          process_node(xml_node)
        end

        true
      end

      private

      attr_accessor :issue_lookup

      def process_node(xml_node)
        logger.info { 'Creating node...' }

        # Create host node
        host_node = content_service.create_node(
          label: xml_node.at_xpath('IP').text,
          type: :host
        )

        %w[dns host_id operating_system qg_hostid tracking_method].each do |key|
          prop = xml_node.at_xpath(key.upcase)
          host_node.set_property(key.to_sym, prop.text) if prop
        end

        tags = xml_node.at_xpath('ASSET_TAGS/ASSET_TAG')
        if tags
          tags.each do |tag|
            host_node.set_property(:asset_tags, tag.text)
          end
        end

        host_node.save

        xml_node.xpath('./VULN_INFO_LIST/VULN_INFO').each do |xml_evidence|
          process_evidence(xml_evidence, host_node)
        end
      end

      def process_issue(xml_vuln)
        qid = xml_vuln.at_xpath('QID').text
        logger.info { "\t => Creating new issue (plugin_id: #{ qid })" }
        issue_text = template_service.process_template(template: 'asset-issue', data: xml_vuln)
        issue = content_service.create_issue(text: issue_text, id: qid)

        issue_lookup[qid.to_i] = issue
      end

      def process_evidence(xml_evidence, node)
        qid = xml_evidence.at_xpath('./QID').text

        issue = issue_lookup[qid.to_i]
        if issue
          issue_id = issue.respond_to?(:id) ? issue.id : issue.to_issue.id

          logger.info { "\t => Creating new evidence (plugin_id: #{qid})" }
          logger.info { "\t\t => Issue: #{issue.title} (plugin_id: #{issue_id})" }
          logger.info { "\t\t => Node: #{node.label} (#{node.id})" }
        else
          logger.info { "\t => Couldn't find QID for issue with ID=#{qid}" }
          return
        end

        evidence_content = template_service.process_template(template: 'asset-evidence', data: xml_evidence)
        content_service.create_evidence(issue: issue, node: node, content: evidence_content)
      end
    end
  end
end
