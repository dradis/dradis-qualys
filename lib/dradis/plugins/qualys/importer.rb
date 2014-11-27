module Dradis::Plugins::Qualys
  class Importer < Dradis::Plugins::Upload::Importer

    attr_accessor :host_node

    # The framework will call this function if the user selects this plugin from
    # the dropdown list and uploads a file.
    # @returns true if the operation was successful, false otherwise
    def import(params={})
      file_content = File.read( params[:file] )

      logger.info{'Parsing Qualys output file...'}
      @doc = Nokogiri::XML( file_content )
      logger.info{'Done.'}

      if @doc.root.name != 'SCAN'
        error = "No scan results were detected in the uploaded file. Ensure you uploaded a Qualys XML file."
        logger.fatal{ error }
        content_service.create_note text: error
        return false
      end

      @doc.xpath('SCAN/IP').each do |xml_host|
        process_ip(xml_host)
      end

      return true
    end

    private

    def process_ip(xml_host)
      host_ip = xml_host['value']
      logger.info{ "Host: %s" % host_ip }

      self.host_node = content_service.create_node(label: host_ip, type: :host)

      host_text = "#[Title]#\nBasic host info\n\n#[Description]#\nIP: #{ host_ip }\nName: #{ xml_host['name'] }\n"
      if (xml_os = xml_host.xpath('OS')) && xml_os.any?
        host_text << "OS: #{ xml_os.text }"
      end
      content_service.create_note text: host_text, node: self.host_node

      # We'll deal with 'VULNS' separately
      ['INFOS', 'SERVICES', 'PRACTICES'].each do |collection|
        xml_host.xpath(collection).each do |xml_collection|
          process_collection(collection, xml_collection)
        end
      end

      # Now we focus on 'VULNS' which we convert into Issue/Evidence
      logger.info{ "Extracting VULNS" }
      xml_host.xpath('VULNS/CAT/VULN').each do |xml_vuln|
        process_vuln(xml_vuln)
      end
    end

    def process_collection(collection, xml_collection)
      collection_node = nil
      xml_cats = xml_collection.xpath('CAT')

      xml_cats.each do |xml_cat|
        logger.info{ "\t#{ collection } - #{ xml_cat['value'] }" }

        if xml_cats.count == 1
          category_node = content_service.create_node(
            label: "#{ collection.downcase } - #{ xml_cats.first['value'] }",
            type: :default,
            parent: self.host_node)
        else
          collection_node ||= content_service.create_node(
            label: collection.downcase,
            type: :default,
            parent: self.host_node)
          category_node = content_service.create_node(
            label: xml_cat['value'],
            type: :default,
            parent: collection_node)
        end

        # For each INFOS/CAT/INFO, SERVICES/CAT/SERVICE, etc.
        xml_cat.xpath(collection.chop).each do |xml_element|
          note_content = template_service.process_template(template: 'element', data: xml_element)

          # retrieve hosts affected by this issue
          note_content << "\n#[host]#\n"
          note_content << self.host_node.label
          note_content << "\n\n"

          content_service.create_note text: note_content, node: category_node
        end
      end
    end

    def process_vuln(xml_vuln)
      vuln_number = xml_vuln[:number]

      logger.info{ "\t\t => Creating new issue (plugin_id: #{ vuln_number })" }
      issue_text = template_service.process_template(template: 'element', data: xml_vuln)
      issue_text << "\n\n#[Number]#\n#{ vuln_number }\n\n"
      issue = content_service.create_issue(text: issue_text, id: vuln_number)

      logger.info{ "\t\t => Creating new evidence" }
      evidence_content = template_service.process_template(template: 'evidence', data: xml_vuln)
      content_service.create_evidence(issue: issue, node: self.host_node, content: evidence_content)
    end
  end
end
