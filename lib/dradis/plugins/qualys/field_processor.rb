module Dradis
  module Plugins
    module Qualys
      class FieldProcessor < Dradis::Plugins::Upload::FieldProcessor

        def post_initialize(args={})
          case data.name
          when 'CAT'
            @cat_object = data
            @qualys_object = ::Qualys::Element.new(data.elements.first)
          when 'QID'
            @qualys_object = ::Qualys::WAS::QID.new(data)
          when 'VULNERABILITY'
            @qualys_object = ::Qualys::WAS::Vulnerability.new(data)
          when 'VULN_DETAILS'
            @qualys_object = ::Qualys::Asset::Vulnerability.new(data)
          when 'VULN_INFO'
            @qualys_object = ::Qualys::Asset::Evidence.new(data)
          end
        end

        def value(args={})
          field = args[:field]

          # Fields in the template are of the form <foo>.<field>, where <foo>
          # is common across all fields for a given template (and meaningless).
          # However we can use it to identify the type of scan we're processing.
          type, name = field.split('.')

          %{element evidence}.include?(type) ? value_network(name) : value_was(name)
        end

        private
        def value_network(name)
          if %w{cat_fqdn cat_misc cat_port cat_protocol cat_value}.include?(name)
            attribute = name[4..-1]
            @cat_object[attribute] || 'n/a'
          else

            if name.end_with?('entries')
              # qualys_object.bid_entries
              # qualys_object.cve_entries
              # qualys_object.xref_entries
              entries = @qualys_object.try(name)
              if entries.any?
                entries.to_a.join("\n")
              else
                'n/a'
              end
            else
              @qualys_object.try(name) || 'n/a'
            end
          end
        end

        def value_was(name)
          @qualys_object.try(name) || 'n/a'
        end
      end
    end
  end
end
