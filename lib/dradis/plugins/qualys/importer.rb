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

      # We treat INFOS, SERVICES, PRACTICES, and VULNS the same way
      # All of these are imported into Dradis as Issues
      ['INFOS', 'SERVICES', 'PRACTICES', 'VULNS'].each do |collection|
        xml_host.xpath(collection).each do |xml_collection|
          process_collection(collection, xml_collection)
        end
      end
    end

    def process_collection(collection, xml_collection)
      collection_node = nil
      xml_cats = xml_collection.xpath('CAT')

      xml_cats.each do |xml_cat|
        logger.info{ "\t#{ collection } - #{ xml_cat['value'] }" }

        empty_dup_xml_cat = xml_cat.dup
        empty_dup_xml_cat.children.remove

        # For each INFOS/CAT/INFO, SERVICES/CAT/SERVICE, VULNS/CAT/VULN, etc.
        xml_cat.xpath(collection.chop).each do |xml_element|
          dup_xml_cat = empty_dup_xml_cat.dup
          dup_xml_cat.add_child(xml_element.dup)
          cat_number = xml_element[:number]

          process_vuln(collection, cat_number, dup_xml_cat)

        end
      end
    end

    # Takes a <CAT> element containing a single <VULN> element and processes an
    # Issue and Evidence template out of it.
    def process_vuln(collection, vuln_number, xml_cat)
      logger.info{ "\t\t => Creating new issue (plugin_id: #{ vuln_number })" }
      issue_text = template_service.process_template(template: 'element', data: xml_cat)
      issue_text << "\n\n#[qualys_collection]#\n#{ collection }"
      issue = content_service.create_issue(text: issue_text, id: vuln_number)

      logger.info{ "\t\t => Creating new evidence" }
      evidence_content = template_service.process_template(template: 'evidence', data: xml_cat)
      content_service.create_evidence(issue: issue, node: self.host_node, content: evidence_content)
    end
  end
end
