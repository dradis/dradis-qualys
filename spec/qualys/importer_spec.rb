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
    %i[node note evidence issue].each do |model|
      allow(content_service).to receive(:"create_#{model}") do |args|
        OpenStruct.new(args)
      end
    end
  end

  let(:example_xml) { 'spec/fixtures/files/simple.xml' }

  pending "collapses INFOS|SERVICES|VULNS|PRACTICES node if only a single element is found"

  def run_import!
    importer.import(file: example_xml)
  end

  it "creates nodes as needed" do
    # Host node
    expect(content_service).to receive(:create_node).with(
      hash_including label: '10.0.155.160'
    ).once
    # Information gathering node
    expect(content_service).to receive(:create_node).with(
      hash_including label: 'infos - Information gathering'
    ).once

    # Services node with its child nodes
    expect(content_service).to receive(:create_node).with(
      hash_including label: 'services'
    ).once
    expect(content_service).to receive(:create_node).with(
      hash_including label: 'TCP/IP'
    ).once
    expect(content_service).to receive(:create_node).with(
      hash_including label: 'Web server'
    ).once

    run_import!
  end


  it "creates notes as needed" do
    # Host node
    expect(content_service).to receive(:create_note) do |args|
      expect(args[:text]).to include("Basic host info")
    end

    # Information gathering node and notes
    expect(content_service).to receive(:create_note) do |args|
      expect(args[:text]).to include("DNS Host Name")
      expect(args[:node].label).to eq("infos - Information gathering")
    end.once
    expect(content_service).to receive(:create_note) do |args|
      expect(args[:text]).to include("Host Scan Time")
      expect(args[:node].label).to eq("infos - Information gathering")
    end.once

    # Child notes of Services node
    expect(content_service).to receive(:create_note) do |args|
      expect(args[:text]).to include("Open TCP Services List")
      expect(args[:node].label).to eq("TCP/IP")
    end.once

    expect(content_service).to receive(:create_note) do |args|
      expect(args[:text]).to include("Web Server Version")
      expect(args[:node].label).to eq("Web server")
    end.once

    run_import!
  end

  # Issues and evidences from vulns
  # There are 3 vulns in total:
  #   - TCP/IP: Sequence number in both hosts
  #   - Web server: Apache 1.3
  #   - Web server: ETag
  # Each one should create 1 issue and 1 evidence

  it "creates issues from vulns" do
    expect(content_service).to receive(:create_issue) do |args|
      expect(args[:text]).to include("Sequence Number Approximation Based Denial of Service")
    end.once

    expect(content_service).to receive(:create_issue) do |args|
      expect(args[:text]).to include("Apache 1.3 HTTP Server Expect Header Cross-Site Scripting")
    end.once

    expect(content_service).to receive(:create_issue) do |args|
      expect(args[:text]).to include("Apache Web Server ETag Header Information Disclosure Weakness")
    end.once

    run_import!
  end

  it "creates evidence from vulns" do
    expect(content_service).to receive(:create_evidence) do |args|
      expect(args[:content]).to include("Tested on port 80 with an injected SYN/RST offset by 16 bytes.")
      expect(args[:issue].text).to include("Sequence Number Approximation Based Denial of Service")
      expect(args[:node].label).to eq("10.0.155.160")
    end.once

    expect(content_service).to receive(:create_evidence) do |args|
      expect(args[:content]).to include("The expectation given in the Expect request-header")
      expect(args[:issue].text).to include("Apache 1.3 HTTP Server Expect Header Cross-Site Scripting")
      expect(args[:node].label).to eq("10.0.155.160")
    end.once

    expect(content_service).to receive(:create_evidence) do |args|
      expect(args[:content]).to include("bee-4f12-00794aef")
      expect(args[:issue].text).to include("Apache Web Server ETag Header Information Disclosure Weakness")
      expect(args[:node].label).to eq("10.0.155.160")
    end.once

    run_import!
  end

  # A VULN is not required to have a RESULT element.
  # See:
  #   https://github.com/securityroots/dradispro-tracker/issues/8
  #   https://qualysapi.qualys.eu/qwebhelp/fo_help/reports/report_dtd.htm
  context "when an issue has no RESULT element" do
    let(:example_xml) { 'spec/fixtures/files/no_result.xml' }

    it "detects an issue without a RESULT element and applies (n/a)" do
      # 1 node should be created:
      expect(content_service).to receive(:create_node).with(
        hash_including label: '10.0.155.160'
      ).once

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

      run_import!
    end
  end

end

