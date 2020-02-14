module Kenna 
  module Toolkit
  class Generator < Kenna::Toolkit::BaseTask
  
    def self.metadata
      {
        id: "generator",
        name: "Generator (of demo data)",
        description: "This task generates some simple demo data!",
        disabled: true,
        options: [
          { :name => "output_directory", 
            :type => "filename", 
            :required => true, 
            :default => "output/generator", 
            :description => "If set, will write a file upon completion. Path is relative to #{$basedir}"  }
        ]
      }
    end
  
    def run(options)
      super
  
      cves = 'CVE-2019-17624
        CVE-2019-8452
        CVE-2019-4013
        CVE-2019-17411
        CVE-2019-11539
        CVE-2019-15741
        CVE-2019-7286
        CVE-2019-14287
        CVE-2019-14538
        CVE-2019-1579
        CVE-2019-11043
        CVE-2018-0919
        CVE-2019-2215
        CVE-2019-17271
        CVE-2019-17132
        CVE-2019-17080
        CVE-2019-11932
        CVE-2018-7251
        CVE-2018-13383
        CVE-2019-16701
        CVE-2019-1367
        CVE-2019-10392
        CVE-2019-10669
        CVE-2019-15029
        CVE-2019-14339
        CVE-2019-16759
        CVE-2019-16679
        CVE-2019-16531
        CVE-2019-1262
        CVE-2019-5485
        CVE-2019-5392
        CVE-2019-16724
        CVE-2015-5287
        CVE-2019-0604
        CVE-2019-13688
        CVE-2019-13687
        CVE-2019-13686
        CVE-2019-13685
        CVE-2019-10393
        CVE-2019-10399
        CVE-2019-10394
        CVE-2019-10400
        CVE-2019-2618
        CVE-2019-2827
        CVE-2018-8004
        CVE-2019-13140
        CVE-2019-14744
        CVE-2019-1257
        CVE-2019-1253
        CVE-2019-1255
        CVE-2018-8581
        CVE-2014-1761
        CVE-2016-5195
        CVE-2012-0158
        CVE-2019-6519
        CVE-2018-17182
        CVE-2019-0808
        CVE-2018-10822
        CVE-2018-16864
        CVE-2018-20251
        CVE-2019-6110
        CVE-2018-16866
        CVE-2013-3906 
        CVE-2019-6111
        CVE-2018-20253
        CVE-2019-3912
        CVE-2019-3462
        CVE-2019-6453
        CVE-2019-1663
        CVE-2019-3911
        CVE-2019-1653
        CVE-2018-16865
        CVE-2010-3333
        CVE-2019-5736
        CVE-2019-8943
        CVE-2018-20252
        CVE-2019-0797
        CVE-2018-15473
        CVE-2018-20250
        CVE-2019-5786
        CVE-2019-6340
        CVE-2018-8629
        CVE-2019-8942
        CVE-2019-0539
        CVE-2019-6447'.split("\n")

    current_time = Time.now.utc

    # prep kdi 
    @assets = []
    @vuln_defs = []

    cves.each do |c|

      generated_ip = "#{rand(255)}.#{rand(255)}.#{rand(255)}.#{rand(255)}"
      cve_name = c.strip
      
      ## Create an asset
      asset_attributes = { :ip_address => generated_ip }
      create_kdi_asset(asset_attributes, :ip_address, ["Randomly Generated", "Another Tag"]) 

      ## Create a vuln
      vuln_attributes = { 
        :ip_address => generated_ip, 
        :scanner_type => "generator",
        :created_at => Time.now.utc,
        :last_seen_at => current_time,
        :scanner_identifier => "#{cve_name}", 
        :status => "open"
      }
      create_kdi_asset_vuln(generated_ip, :ip_address, vuln_attributes)

      ## Create a vuln def
      vuln_def_attributes = {
        :scanner_type => "generator",
        :scanner_identifier => "#{cve_name}"
      }
      create_kdi_vuln_def(vuln_def_attributes) 
    end

      kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }

      # create output dir
      if @options[:output_directory]
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        FileUtils.mkdir_p output_dir
        
        # create full output path
        output_path = "#{output_dir}/generator.kdi.json"

        print_good "Output being written to: #{output_path}"
        File.open(output_path,"w") {|f| f.puts JSON.pretty_generate(kdi_output) } 
      end
    
    end
    
  end
  end
  end