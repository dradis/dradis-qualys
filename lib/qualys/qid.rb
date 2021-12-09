module Qualys
  # This class represents each of the WAS_SCAN_REPORT/GLOSSARY/QID_LIST/QID
  # elements in the Qualys WAS XML document.
  #
  # It provides a convenient way to access the information scattered all over
  # the XML in attributes and nested tags.
  #
  # Instead of providing separate methods for each supported property we rely
  # on Ruby's #method_missing to do most of the work.
  class QID
    # Accepts an XML node from Nokogiri::XML.
    def initialize(xml_node)
      @xml = xml_node
    end

    # List of supported tags. They can be attributes, simple descendans or
    # collections (e.g. <references/>, <tags/>)
    def supported_tags
      [
        # simple tags
        :category, :cwe, :description, :group, :impact, :owasp, :qid,
        :severity, :solution, :title, :wasc,

        :cvss_base, :cvss_temporal, :cvss3_base, :cvss3_temporal, :cvss3_vector
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

      method_name = method.to_s

      # Then we try simple children tags: TITLE, LAST_UPDATE, CVSS_BASE...
      tag = @xml.at_xpath("./#{method_name.upcase}")
      if tag && !tag.text.blank?
        if tags_with_html_content.include?(method)
          return Qualys::cleanup_html(tag.text)
        else
          return tag.text
        end
      else
        'n/a'
      end
    end

    private
    def tags_with_html_content
      [:description, :impact, :solution]
    end
  end
end
