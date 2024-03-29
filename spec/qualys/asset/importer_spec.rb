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

      @importer = Dradis::Plugins::Qualys::Asset::Importer.new(
        content_service: @content_service
      )
    end

    let(:example_xml) { 'spec/fixtures/files/simple_asset.xml' }
    let(:run_import!) { @importer.import(file: example_xml) }

    it 'creates nodes as needed' do
      expect_to_create_node_with(label: '10.0.0.1')
      run_import!
    end

    it 'creates issues as needed' do
      expect_to_create_issue_with(text: 'Hidden RPC Services')
      run_import!
    end

    it 'creates evidence as needed' do
      expect_to_create_evidence_with(
        content: 'http://example.com',
        issue: 'Hidden RPC Services',
        node_label: '10.0.2.8'
      )
      run_import!
    end
  end
end
