module Dradis::Plugins::Qualys
  class MappingService
    def default_mapping
      {
        'asset-evidence' => {
          'Result' => '{{ asset-evidence.result }}',
          'Status' => '{{ asset-evidence.vuln_status }}',
          'SSL' => '{{ asset-evidence.ssl }}',
          'CVSSv3.Final' => '{{ asset-evidence.cvss_final }}'
        },
        'asset-issue' => {
          'Title' => '{{ asset-issue.title }}',
          'Severity' => '{{ asset-issue.severity }}',
          'Categories' => 'Category: {{ asset-issue.category }}',
          'CVSSv3.BaseScore' => '{{ asset-issue.cvss3_base }}',
          'CVSSv3.TemporalScore' => '{{ asset-issue.cvss3_temporal }}',
          'Threat' => '{{ asset-issue.threat }}',
          'Impact' => '{{ asset-issue.impact }}',
          'Solution' => '{{ asset-issue.solution }}'
        },
        'element' => {
          'Title' => '{{ element.title }}',
          'Severity' => '{{ element.severity }}',
          'CVE' => '{{ element.cveid }}',
          'CVSS' => "Base: {{ element.cvss_base }}\n
                    Temporal: {{ element.cvss_temporal }}",
          'Diagnosis' => '{{ element.diagnosis }}',
          'Consequence' => '{{ element.consequence }}',
          'Solution' => '{{ element.solution }}',
          'Result' => '{{ element.result }}',
          'CVEList' => '{{ element.cve_id_list }}',
          'QualysCollection' => '{{ element.qualys_collection }}'
        },
        'evidence' => {
          'Category' => '{{ evidence.cat_value }}',
          'Protocol' => '{{ evidence.cat_protocol }}',
          'Port' => '{{ evidence.cat_port }}',
          'Output' => '{{ evidence.result }}'
        },
        'was-evidence' => {
          'Location' => '{{ was-evidence.url }}',
          'Output' => "*Request*\n\n
                      Method: {{ was-evidence.request_method }}\n
                      URL: {{ was-evidence.request_url }}\n\n
                      bc.. {{ was-evidence.request_headers }}\n\n
                      p. *Response*\n\n
                      Evidence: {{ was-evidence.response_evidence }}\n\n
                      bc.. {{ was-evidence.response_contents }}"
        },
        'was-issue' => {
          'Title' => '{{ was-issue.title }}',
          'Severity' => '{{ was-issue.severity }}',
          'Categories' => "Category: {{ was-issue.category }}\n
                          Group: {{ was-issue.group }}\n
                          OWASP: {{ was-issue.owasp }}\n
                          CWE: {{ was-issue.cwe }}",
          'CVSSv3.Vector' => '{{ was-issue.cvss3_vector }}',
          'CVSSv3.BaseScore' => '{{ was-issue.cvss3_base }}',
          'CVSSv3.TemporalScore' => '{{ was-issue.cvss3_temporal }}',
          'Description' => '{{ was-issue.description }}',
          'Impact' => '{{ was-issue.impact }}',
          'Solution' => '{{ was-issue.solution }}'
        }
      }
    end
  end
end
