require 'spec_helper'
require 'ostruct'

module Dradis::Plugins
  describe 'Qualys upload plugin' do
    before(:each) do
      # Stub template service
      templates_dir = File.expand_path('../../../../templates', __FILE__)
      expect_any_instance_of(Dradis::Plugins::TemplateService)
      .to receive(:default_templates_dir).and_return(templates_dir)

      stub_content_service

      @importer = Dradis::Plugins::Qualys::Vuln::Importer.new(
        content_service: @content_service
      )
    end

    let(:example_xml) { 'spec/fixtures/files/simple.xml' }

    def run_import!
      @importer.import(file: example_xml)
    end

    it "creates nodes as needed" do
      expect_to_create_node_with(label: '10.0.155.160')

      run_import!
    end

    # Issues and evidences from vulns
    # There are 7 vulns/infos/services in total:
    #   - DNS Host Name
    #   - Host Scan Time
    #   - Open TCP Services List
    #   - Web Server Version
    #   - TCP/IP: Sequence number in both hosts
    #   - Web server: Apache 1.3
    #   - Web server: ETag

    it "creates issues from vulns" do
      expect_to_create_issue_with(
        text: "DNS Host Name"
      )

      expect_to_create_issue_with(
        text: "Host Scan Time"
      )

      expect_to_create_issue_with(
        text: "Open TCP Services List"
      )

      expect_to_create_issue_with(
        text: "Web Server Version"
      )

      expect_to_create_issue_with(
        text: "TCP Sequence Number Approximation Based Denial of Service"
      )

      expect_to_create_issue_with(
        text: "Apache 1.3 HTTP Server Expect Header Cross-Site Scripting"
      )

      expect_to_create_issue_with(
          text: "Apache Web Server ETag Header Information Disclosure Weakness",
          text: "OpenBSD has released a \"patch\":ftp://ftp.openbsd.org/pub/OpenBSD/patches/3.2/common/008_httpd.patch that fixes this vulnerability. After installing the patch, inode numbers returned from the server are encoded using a private hash to avoid the release of sensitive information.\n\n\n\nCustomers"
      )

      run_import!
    end

    it "creates evidence from vulns" do
      expect_to_create_evidence_with(
        content: "IP address\tHost name\n10.0.155.160\tNo registered hostname\n",
        issue: "DNS Host Name",
        node_label: "10.0.155.160"
      )

      expect_to_create_evidence_with(
        content: "Scan duration: 5445 seconds\n\nStart time: Fri, Dec 20 2011, 17:38:59 GMT\n\nEnd time: Fri, Dec 20 2011, 19:09:44 GMT",
        issue: "Host Scan Time",
        node_label: "10.0.155.160"
      )

      expect_to_create_evidence_with(
        content: "\tDescription\tService Detected\tOS On Redirected Port\n80\twww\tWorld Wide Web HTTP\thttp",
        issue: "Open TCP Services List",
        node_label: "10.0.155.160"
      )

      expect_to_create_evidence_with(
        content: "Server Version\tServer Banner\nApache 1.3\tApache",
        issue: "Web Server Version",
        node_label: "10.0.155.160"
      )

      expect_to_create_evidence_with(
        content: "Tested on port 80 with an injected SYN/RST offset by 16 bytes.",
        issue: "TCP Sequence Number Approximation Based Denial of Service",
        node_label: "10.0.155.160"
      )
      expect_to_create_evidence_with(
        content: "HTTP/1.1 417 Expectation Failed\nDate: Fri, 20 Dec 2011 19:05:57 GMT",
        issue: "Apache 1.3 HTTP Server Expect Header Cross-Site Scripting",
        node_label: "10.0.155.160"
      )
      expect_to_create_evidence_with(
        content: "3bee-4f12-00794aef",
        issue: "Apache Web Server ETag Header Information Disclosure Weakness",
        node_label: "10.0.155.160"
      )

      run_import!
    end

    # A VULN is not required to have a RESULT element.
    # See:
    #   https://github.com/securityroots/dradispro-tracker/issues/8
    #   https://qualysapi.qualys.eu/qwebhelp/fo_help/reports/report_dtd.htm
    context "when an issue has no RESULT element" do
      #let(:example_xml) { 'spec/fixtures/files/no_result.xml' }

      it "detects an issue without a RESULT element and applies (n/a) and strips/replaces formatting tags" do
        # 1 node should be created:
        expect_to_create_node_with(label: '10.0.155.160')

        # There is 1 vuln in total:
        #   - TCP/IP: Sequence number in both hosts
        # Each one should create 1 issue and 1 evidence
        expect_to_create_issue_with(
          text: "Sequence Number Approximation Based Denial of Service",
          text: "Please first check the results section below for the port number on which this vulnerability was detected. If that port number is known to be used for port-forwarding, then it is the backend host that is really vulnerable.\n\n\n\nVarious implementations and products including Check Point, Cisco, Cray Inc, Hitachi, Internet Initiative Japan, Inc (IIJ), Juniper Networks, NEC, Polycom, and Yamaha are currently undergoing review. Contact the vendors to obtain more information about affected products and fixes. \"NISCC Advisory 236929 - Vulnerability Issues in TCP\":http://packetstormsecurity.org/0404-advisories/246929.html details the vendor patch status as of the time of the advisory, and identifies resolutions and workarounds."
        )

        expect_to_create_evidence_with(
          content: "n/a",
          issue: "Sequence Number Approximation Based Denial of Service",
          node_label: "10.0.155.160"
        )

        @importer.import(file: 'spec/fixtures/files/no_result.xml')
      end
    end

    context 'VULN with ciphers' do
      it 'wraps cipher in code block' do
        expect_to_create_issue_with(
          text: "\nbc. SSLCipherSuite RC4-SHA:HIGH:!ADH"
        )

        @importer.import(file: 'spec/fixtures/files/with_ciphers.xml')
      end
    end

    def expect_to_create_node_with(label:)
      expect(@content_service).to receive(:create_node).with(
        hash_including label: label
      ).once
    end

    def expect_to_create_issue_with(text:)
      expect(@content_service).to receive(:create_issue) do |args|
        expect(args[:text]).to include text
        OpenStruct.new(args)
      end.once
    end

    def expect_to_create_evidence_with(content:, issue:, node_label:)
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include content
        expect(args[:issue].text).to include issue
        expect(args[:node].label).to eq node_label
      end.once
    end

  end
end
