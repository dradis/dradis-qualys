module Dradis::Plugins::Qualys
  module Mapping
    def self.default_mapping
      {
        'asset-evidence' => {
          'Result' => '{{ qualys[asset-evidence.result] }}',
          'Status' => '{{ qualys[asset-evidence.vuln_status] }}',
          'SSL' => '{{ qualys[asset-evidence.ssl] }}',
          'CVSSv3.Final' => '{{ qualys[asset-evidence.cvss_final] }}'
        },
        'asset-issue' => {
          'Title' => '{{ qualys[asset-issue.title] }}',
          'Severity' => '{{ qualys[asset-issue.severity] }}',
          'Categories' => 'Category: {{ qualys[asset-issue.category] }}',
          'CVSSv3.BaseScore' => '{{ qualys[asset-issue.cvss3_base] }}',
          'CVSSv3.TemporalScore' => '{{ qualys[asset-issue.cvss3_temporal] }}',
          'Threat' => '{{ qualys[asset-issue.threat] }}',
          'Impact' => '{{ qualys[asset-issue.impact] }}',
          'Solution' => '{{ qualys[asset-issue.solution] }}'
        },
        'element' => {
          'Title' => '{{ qualys[element.title] }}',
          'Severity' => '{{ qualys[element.severity] }}',
          'CVE' => '{{ qualys[element.cveid] }}',
          'CVSS' => "Base: {{ qualys[element.cvss_base] }}\n
                    Temporal: {{ qualys[element.cvss_temporal] }}",
          'Diagnosis' => '{{ qualys[element.diagnosis] }}',
          'Consequence' => '{{ qualys[element.consequence] }}',
          'Solution' => '{{ qualys[element.solution] }}',
          'Result' => '{{ qualys[element.result] }}',
          'CVEList' => '{{ qualys[element.cve_id_list] }}',
          'QualysCollection' => '{{ qualys[element.qualys_collection] }}'
        },
        'evidence' => {
          'Category' => '{{ qualys[evidence.cat_value] }}',
          'Protocol' => '{{ qualys[evidence.cat_protocol] }}',
          'Port' => '{{ qualys[evidence.cat_port] }}',
          'Output' => '{{ qualys[evidence.result] }}'
        },
        'was-evidence' => {
          'Location' => '{{ qualys[was-evidence.url] }}',
          'Output' => "*Request*\n\n
                      Method: {{ qualys[was-evidence.request_method] }}\n
                      URL: {{ qualys[was-evidence.request_url] }}\n\n
                      bc.. {{ qualys[was-evidence.request_headers] }}\n\n
                      p. *Response*\n\n
                      Evidence: {{ qualys[was-evidence.response_evidence] }}\n\n
                      bc.. {{ qualys[was-evidence.response_contents] }}"
        },
        'was-issue' => {
          'Title' => '{{ qualys[was-issue.title] }}',
          'Severity' => '{{ qualys[was-issue.severity] }}',
          'Categories' => "Category: {{ qualys[was-issue.category] }}\n
                          Group: {{ qualys[was-issue.group] }}\n
                          OWASP: {{ qualys[was-issue.owasp] }}\n
                          CWE: {{ qualys[was-issue.cwe] }}",
          'CVSSv3.Vector' => '{{ qualys[was-issue.cvss3_vector] }}',
          'CVSSv3.BaseScore' => '{{ qualys[was-issue.cvss3_base] }}',
          'CVSSv3.TemporalScore' => '{{ qualys[was-issue.cvss3_temporal] }}',
          'Description' => '{{ qualys[was-issue.description] }}',
          'Impact' => '{{ qualys[was-issue.impact] }}',
          'Solution' => '{{ qualys[was-issue.solution] }}'
        }
      }
    end

    # since renaming template files to use a consistent structure,
    # we need a reference to the old names in order to migrate the
    # .template files to mapping records in the db
    # { new_template_name => old_template_name }
    def self.legacy_mapping_reference
      {
        'asset_evidence' => 'asset-evidence',
        'asset_issue' => 'asset-issue',
        'vuln_evidence' => 'evidence',
        'vuln_element' => 'element',
        'was_evidence' => 'was-evidence',
        'was_issue' => 'was-issue'
      }
    end
  end
end
