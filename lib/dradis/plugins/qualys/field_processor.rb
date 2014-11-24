module Dradis
  module Plugins
    module Qualys
      class FieldProcessor < Dradis::Plugins::Upload::FieldProcessor

        def post_initialize(args={})
          @qualys_object = ::Qualys::Element.new(data)
        end

        def value(args={})
          field = args[:field]

          # fields in the template are of the form <foo>.<field>, where <foo>
          # is common across all fields for a given template (and meaningless).
          _, name = field.split('.')

          if name.end_with?('entries')
            # report_item.bid_entries
            # report_item.cve_entries
            # report_item.xref_entries
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
    end
  end
end