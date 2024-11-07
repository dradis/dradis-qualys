class QualysTasks < Thor
  include Rails.application.config.dradis.thor_helper_module

  namespace "dradis:plugins:qualys:upload"

  desc "vuln FILE", "upload Qualys Vuln XML results"
  def vuln(file_path)
    require 'config/environment'

    unless File.exists?(file_path)
      $stderr.puts "** the file [#{file_path}] does not exist"
      exit -1
    end

    detect_and_set_project_scope

    importer = Dradis::Plugins::Qualys::Vuln::Importer.new(task_options)
    importer.import(file: file_path)
  end

  desc "was FILE", "upload Qualys WAS XML results"
  def was(file_path)
    require 'config/environment'

    unless File.exists?(file_path)
      $stderr.puts "** the file [#{file_path}] does not exist"
      exit -1
    end

    detect_and_set_project_scope

    importer = Dradis::Plugins::Qualys::WAS::Importer.new(task_options)
    importer.import(file: file_path)
  end
end
