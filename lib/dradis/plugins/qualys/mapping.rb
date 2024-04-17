module Dradis::Plugins::Qualys
  module Mapping
    DEFAULT_MAPPING = {
      asset_evidence: {
        'Result' => '{{ qualys[asset-evidence.result] }}',
        'Status' => '{{ qualys[asset-evidence.vuln_status] }}',
        'SSL' => '{{ qualys[asset-evidence.ssl] }}',
        'CVSSv3.Final' => '{{ qualys[asset-evidence.cvss_final] }}'
      },
      asset_issue: {
        'Title' => '{{ qualys[asset-issue.title] }}',
        'Severity' => '{{ qualys[asset-issue.severity] }}',
        'Categories' => 'Category: {{ qualys[asset-issue.category] }}',
        'CVSSv3.BaseScore' => '{{ qualys[asset-issue.cvss3_base] }}',
        'CVSSv3.TemporalScore' => '{{ qualys[asset-issue.cvss3_temporal] }}',
        'Threat' => '{{ qualys[asset-issue.threat] }}',
        'Impact' => '{{ qualys[asset-issue.impact] }}',
        'Solution' => '{{ qualys[asset-issue.solution] }}'
      },
      vuln_element: {
        'Title' => '{{ qualys[element.title] }}',
        'Severity' => '{{ qualys[element.severity] }}',
        'CVE' => '{{ qualys[element.cveid] }}',
        'CVSS' => "Base: {{ qualys[element.cvss_base] }}\nTemporal: {{ qualys[element.cvss_temporal] }}",
        'Diagnosis' => '{{ qualys[element.diagnosis] }}',
        'Consequence' => '{{ qualys[element.consequence] }}',
        'Solution' => '{{ qualys[element.solution] }}',
        'Result' => '{{ qualys[element.result] }}',
        'CVEList' => '{{ qualys[element.cve_id_list] }}',
        'QualysCollection' => '{{ qualys[element.qualys_collection] }}'
      },
      vuln_evidence: {
        'Category' => '{{ qualys[evidence.cat_value] }}',
        'Protocol' => '{{ qualys[evidence.cat_protocol] }}',
        'Port' => '{{ qualys[evidence.cat_port] }}',
        'Output' => '{{ qualys[evidence.result] }}'
      },
      was_evidence: {
        'Location' => '{{ qualys[was-evidence.url] }}',
        'Output' => "*Request*\n\nMethod: {{ qualys[was-evidence.request_method] }}\nURL: {{ qualys[was-evidence.request_url] }}\n\nbc.. {{ qualys[was-evidence.request_headers] }}\n\np. *Response*\n\nEvidence: {{ qualys[was-evidence.response_evidence] }}\n\nbc.. {{ qualys[was-evidence.response_contents] }}"
      },
      was_issue: {
        'Title' => '{{ qualys[was-issue.title] }}',
        'Severity' => '{{ qualys[was-issue.severity] }}',
        'Categories' => "Category: {{ qualys[was-issue.category] }}\nGroup: {{ qualys[was-issue.group] }}\nOWASP: {{ qualys[was-issue.owasp] }}\nCWE: {{ qualys[was-issue.cwe] }}",
        'CVSSv3.Vector' => '{{ qualys[was-issue.cvss3_vector] }}',
        'CVSSv3.BaseScore' => '{{ qualys[was-issue.cvss3_base] }}',
        'CVSSv3.TemporalScore' => '{{ qualys[was-issue.cvss3_temporal] }}',
        'Description' => "{{ qualys[was-issue.description] }}\n\n{{ qualys[was-issue.impact] }}",
        'Solution' => '{{ qualys[was-issue.solution] }}'
      }
    }.freeze

    SOURCE_FIELDS = {
      asset_evidence: [
        'asset-evidence.cvss3_final',
        'asset-evidence.cvss_final',
        'asset-evidence.first_found',
        'asset-evidence.last_found',
        'asset-evidence.result',
        'asset-evidence.ssl',
        'asset-evidence.times_found',
        'asset-evidence.type',
        'asset-evidence.vuln_status'
      ],
      asset_issue: [
        'asset-issue.category',
        'asset-issue.cvss3_base',
        'asset-issue.cvss3_temporal',
        'asset-issue.cvss_base',
        'asset-issue.cvss_temporal',
        'asset-issue.impact',
        'asset-issue.last_update',
        'asset-issue.pci_flag',
        'asset-issue.qid',
        'asset-issue.result',
        'asset-issue.severity',
        'asset-issue.solution',
        'asset-issue.threat',
        'asset-issue.title'
      ],
      vuln_element: [
        'element.number',
        'element.severity',
        'element.cveid',
        'element.title',
        'element.last_update',
        'element.cvss_base',
        'element.cvss_temporal',
        'element.pci_flag',
        'element.vendor_reference_list',
        'element.cve_id_list',
        'element.bugtraq_id_list',
        'element.diagnosis',
        'element.consequence',
        'element.solution',
        'element.compliance',
        'element.result',
        'element.qualys_collection'
      ],
      vuln_evidence: [
        'evidence.cat_fqdn',
        'evidence.cat_misc',
        'evidence.cat_port',
        'evidence.cat_protocol',
        'evidence.cat_value',
        'evidence.result'
      ],
      was_evidence: [
        'was-evidence.access_paths',
        'was-evidence.ajax',
        'was-evidence.authentication',
        'was-evidence.ignored',
        'was-evidence.potential',
        'was-evidence.request_headers',
        'was-evidence.request_method',
        'was-evidence.request_url',
        'was-evidence.response_contents',
        'was-evidence.response_evidence',
        'was-evidence.url'
      ],
      was_issue: [
        'was-issue.category',
        'was-issue.cvss_base',
        'was-issue.cvss_temporal',
        'was-issue.cvss3_base',
        'was-issue.cvss3_temporal',
        'was-issue.cvss3_vector',
        'was-issue.cwe',
        'was-issue.description',
        'was-issue.group',
        'was-issue.impact',
        'was-issue.owasp',
        'was-issue.qid',
        'was-issue.severity',
        'was-issue.solution',
        'was-issue.title',
        'was-issue.wasc'
      ]
    }.freeze
  end
end
