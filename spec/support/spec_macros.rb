module SpecMacros
  extend ActiveSupport::Concern

  def stub_content_service
    # Init services
    plugin = Dradis::Plugins::Qualys

    @content_service = Dradis::Plugins::ContentService::Base.new(
      logger: Logger.new(STDOUT),
      plugin: plugin
    )

    # Stub dradis-plugins methods
    #
    # They return their argument hashes as objects mimicking
    # Nodes, Issues, etc
    allow(@content_service).to receive(:create_node) do |args|
      obj = OpenStruct.new(args)
      obj.define_singleton_method(:set_property) { |_, __| }
      obj
    end
    allow(@content_service).to receive(:create_issue) do |args|
      OpenStruct.new(args)
    end
    allow(@content_service).to receive(:create_evidence) do |args|
      OpenStruct.new(args)
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
