require 'fileutils'
require 'json'
#FileUtils.mkdir_p "/Users/yiccheng/OneDrive - Cisco/Effany- Cisco_/KennaRepos/toolkit/newDirTest"


def write_file_stream(directory, filename)
    output_path = "#{directory}/#{filename}" # FIXME: The method should just take a path,
    FileUtils.mkdir_p directory # FIXME: then this could be File.basename(path)

    obj = {
      "skip_autoclose" => false,
      "version" => 1,
      "assets" => "nothing",
      "vuln_defs" => "defs"
    }

    File.open(output_path, 'w') do |file|
      JSON.dump(obj, file)
    end
  end

write_file_stream("output2/github_secret_scanning", "test file")