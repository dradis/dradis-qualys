module Qualys::Asset
  # This class represents each of the ASSET_DATA_REPORT/GLOSSARY/VULN_INFO_LIST/
  # VULN_INFO elements in the Qualys Asset XML document.
  #
  # It provides a convenient way to access the information scattered all over
  # the XML in attributes and nested tags.
  #
  # Instead of providing separate methods for each supported property we rely
  # on Ruby's #method_missing to do most of the work.
  class Evidence
    # Accepts an XML node from Nokogiri::XML.
    def initialize(xml_node)
      @xml = xml_node
    end

    # List of supported tags. They can be attributes, simple descendans or
    # collections (e.g. <references/>, <tags/>)
    def supported_tags
      [
        # simple tags
        :first_round, :last_round, :result, :ssl, :times_found,
        :type, :vuln_status,

        :cvss_base, :cvss3_final
      ]
    end

    # This allows external callers (and specs) to check for implemented
    # properties
    def respond_to?(method, include_private=false)
      return true if supported_tags.include?(method.to_sym)
      super
    end

    # This method is invoked by Ruby when a method that is not defined in this
    # instance is called.
    #
    # In our case we inspect the @method@ parameter and try to find the
    # attribute, simple descendent or collection that it maps to in the XML
    # tree.
    def method_missing(method, *args)
      # We could remove this check and return nil for any non-recognized tag.
      # The problem would be that it would make tricky to debug problems with
      # typos. For instance: <>.potr would return nil instead of raising an
      # exception
      unless supported_tags.include?(method)
        super
        return
      end

      process_field_value(method.to_s)
    end

    def process_field_value(method)
      tag = @xml.at_xpath("./#{method.upcase}")

      if tag && !tag.text.blank?
        if tags_with_html_content.include?(method)
          Qualys.cleanup_html(tag.text)
        else
          tag.text
        end
      else
        'n/a'
      end
    end

    private

    def tags_with_html_content
      %w[result]
    end
  end
end
