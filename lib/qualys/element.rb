module Qualys

  def self.cleanup_html(source)
    result = source.dup
    result.gsub!(/&quot;/, '"')
    result.gsub!(/&lt;/, '<')
    result.gsub!(/&gt;/, '>')

    result.gsub!(/<p>/i, "\n\n")
    result.gsub!(/<br>/i, "\n")
    result.gsub!(/          /, "")
    result.gsub!(/<a href=\"(.*?)\"\s?target=\"_blank\">(.*?)<\/a>/i) { "\"#{$2.strip}\":#{$1.strip}" }
    result.gsub!(/<pre>(.*?)<\/pre>/im) { |m| "\n\nbc.. #{$1.strip}\n\np.  \n" }
    result.gsub!(/<b>(.*?)<\/b>/i) { "*#{$1.strip}*" }
    result.gsub!(/<b>|<\/b>/i, "")
    result.gsub!(/<i>(.*?)<\/i>/i) { "_#{$1.strip}_" }

    result.gsub!(/<dl>|<\/dl>/i, "\n")
    result.gsub!(/<dt>(.*?)<\/dt>/i) { "* #{$1.strip}" }
    result.gsub!(/<dd>(.*?)<\/dd>/i) { "** #{$1.strip}" }
    result
  end


  # This class represents each of the /SCAN/IP/[INFOS|SERVICES|VULNS|PRACTICES]/CAT/[INFO|SERVICE|VULN|PRACTICE]
  # elements in the Qualys XML document.
  #
  # It provides a convenient way to access the information scattered all over
  # the XML in attributes and nested tags.
  #
  # Instead of providing separate methods for each supported property we rely
  # on Ruby's #method_missing to do most of the work.
  class Element
    SSL_CIPHER_VULN_IDS = %w[38140 38141 42366 86729].freeze

    # Accepts an XML node from Nokogiri::XML.
    def initialize(xml_node)
      @xml = xml_node
    end

    # List of supported tags. They can be attributes, simple descendans or
    # collections (e.g. <references/>, <tags/>)
    def supported_tags
      [
        # attributes
        :number, :severity, :cveid,

        # simple tags
        :title, :last_update, :cvss3_base, :cvss3_temporal, :cvss3_version, :cvss_base,
        :cvss_temporal, :pci_flag, :diagnosis, :consequence, :solution, :compliance, :result,

        # multiple tags
        :vendor_reference_list, :cve_id_list, :bugtraq_id_list,

        # category
        :qualys_collection
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

      # First we try the attributes. In Ruby we use snake_case, but in XML
      # CamelCase is used for some attributes
      # translations_table = {
      #   :nexpose_id => 'id',
      #   :pci_severity => 'pciSeverity',
      #   :cvss_score => 'cvssScore',
      #   :cvss_vector =>'cvssVector'
      # }
      #
      # method_name = translations_table.fetch(method, method.to_s)
      method_name = method.to_s
      return @xml.attributes[method_name].value if @xml.attributes.key?(method_name)

      tag = @xml.at_xpath("./#{method_name.upcase}")
      if method_name == 'qualys_collection'
        @xml.name
      elsif tag && !tag.text.blank?
        vuln_id = @xml.attributes['number'].to_s
        cleanup_tag(method, vuln_id, tag.text)
      else
        # nothing found, the tag is valid but not present in this ReportItem
        return nil
      end
    end

    private

    def add_bc_to_ssl_cipher_list(source)
      result = source
      result.gsub!(/^(.*?):!(.*?)$/) { "\nbc. #{$1}:!#{$2}\n" }
      result
    end

    def cleanup_tag(method, vuln_id, text)
      result = text
      result = Qualys::cleanup_html(result) if tags_with_html_content.include?(method)
      result = add_bc_to_ssl_cipher_list(result) if SSL_CIPHER_VULN_IDS.include?(vuln_id)
      result
    end

    def tags_with_html_content
      [:consequence, :diagnosis, :solution]
    end
  end
end
