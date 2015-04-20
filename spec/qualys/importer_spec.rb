require "spec_helper"
require "ostruct"

describe Dradis::Plugins::Qualys::Importer do
  let(:plugin) { Dradis::Plugins::Qualys }

  let(:content_service)  { Dradis::Plugins::ContentService.new(plugin: plugin) }
  let(:template_service) { Dradis::Plugins::TemplateService.new(plugin: plugin) }

  let(:importer) {
    described_class.new(
      content_service: content_service,
      template_service: template_service
    )
  }

  before do
    # Stub template service
    templates_dir = File.expand_path('../../../templates', __FILE__)
    allow_any_instance_of(Dradis::Plugins::TemplateService).to \
      receive(:default_templates_dir).and_return(templates_dir)

    # Stub dradis-plugins methods
    #
    # They return their argument hashes as objects mimicking
    # Nodes, Issues, etc
    allow(content_service).to receive(:create_node) do |args|
      OpenStruct.new(args)
    end
    allow(content_service).to receive(:create_note) do |args|
      OpenStruct.new(args)
    end
  end

  pending "collapses INFOS|SERVICES|VULNS|PRACTICES node if only a single element is found"

  it "creates nodes, issues, notes and an evidences as needed" do

    # Host node and basic host info note
    expect(content_service).to receive(:create_node).with(hash_including label: '10.0.155.160').once
    expect(content_service).to receive(:create_note) do |args|
      expect(args[:text]).to include("Basic host info")
    end.once

    # Information gathering node and notes
    expect(content_service).to receive(:create_node).with(hash_including label: 'infos - Information gathering').once
    expect(content_service).to receive(:create_note) do |args|
      expect(args[:text]).to include("DNS Host Name")
      expect(args[:node].label).to eq("infos - Information gathering")
    end.once
    expect(content_service).to receive(:create_note) do |args|
      expect(args[:text]).to include("Host Scan Time")
      expect(args[:node].label).to eq("infos - Information gathering")
    end.once

    # Services node with its child nodes and notes
    expect(content_service).to receive(:create_node).with(hash_including label: 'services').once

    expect(content_service).to receive(:create_node).with(hash_including label: 'TCP/IP').once
    expect(content_service).to receive(:create_note) do |args|
      expect(args[:text]).to include("Open TCP Services List")
      expect(args[:node].label).to eq("TCP/IP")
    end.once

    expect(content_service).to receive(:create_node).with(hash_including label: 'Web server').once
    expect(content_service).to receive(:create_note) do |args|
      expect(args[:text]).to include("Web Server Version")
      expect(args[:node].label).to eq("Web server")
    end.once

    # Issues and evidences from vulns
    # There are 3 vulns in total:
    #   - TCP/IP: Sequence number in both hosts
    #   - Web server: Apache 1.3
    #   - Web server: ETag
    # Each one should create 1 issue and 1 evidence
    expect(content_service).to receive(:create_issue) do |args|
      expect(args[:text]).to include("Sequence Number Approximation Based Denial of Service")
      OpenStruct.new(args)
    end.once
    expect(content_service).to receive(:create_evidence) do |args|
      expect(args[:content]).to include("Tested on port 80 with an injected SYN/RST offset by 16 bytes.")
      expect(args[:issue].text).to include("Sequence Number Approximation Based Denial of Service")
      expect(args[:node].label).to eq("10.0.155.160")
    end.once

    expect(content_service).to receive(:create_issue) do |args|
      expect(args[:text]).to include("Apache 1.3 HTTP Server Expect Header Cross-Site Scripting")
      OpenStruct.new(args)
    end.once
    expect(content_service).to receive(:create_evidence) do |args|
      expect(args[:content]).to include("The expectation given in the Expect request-header")
      expect(args[:issue].text).to include("Apache 1.3 HTTP Server Expect Header Cross-Site Scripting")
      expect(args[:node].label).to eq("10.0.155.160")
    end.once

    expect(content_service).to receive(:create_issue) do |args|
      expect(args[:text]).to include("Apache Web Server ETag Header Information Disclosure Weakness")
      OpenStruct.new(args)
    end.once
    expect(content_service).to receive(:create_evidence) do |args|
      expect(args[:content]).to include("bee-4f12-00794aef")
      expect(args[:issue].text).to include("Apache Web Server ETag Header Information Disclosure Weakness")
      expect(args[:node].label).to eq("10.0.155.160")
    end.once

    # Run the import
    importer.import(file: 'spec/fixtures/files/simple.xml')
  end

  # A VULN is not required to have a RESULT element.
  # See:
  #   https://github.com/securityroots/dradispro-tracker/issues/8
  #   https://qualysapi.qualys.eu/qwebhelp/fo_help/reports/report_dtd.htm
  it "detects an issue without a RESULT element and applies (n/a)" do
    # 1 node should be created:
    expect(content_service).to receive(:create_node).with(hash_including label: '10.0.155.160').once

    # There is 1 vuln in total:
    #   - TCP/IP: Sequence number in both hosts
    # Each one should create 1 issue and 1 evidence
    expect(content_service).to receive(:create_issue) do |args|
      expect(args[:text]).to include("Sequence Number Approximation Based Denial of Service")
      OpenStruct.new(args)
    end.once
    expect(content_service).to receive(:create_evidence) do |args|
      expect(args[:content]).to include("n/a")
      expect(args[:issue].text).to include("Sequence Number Approximation Based Denial of Service")
      expect(args[:node].label).to eq("10.0.155.160")
    end.once

    # Run the import
    importer.import(file: 'spec/fixtures/files/no_result.xml')
  end

end

