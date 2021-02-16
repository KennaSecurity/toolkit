# frozen_string_literal: true

require_relative "issue_mapping"

module Kenna
  module Toolkit
    module ExpanseIssues
      module Mapper
        include Kenna::Toolkit::KdiHelpers
        include Kenna::Toolkit::ExpanseIssues::IssueMapping

        def kdi_kickoff
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        end

        def snake_case(issue_type)
          it = issue_type.gsub(/(.)([A-Z])/, '\1_\2')
          it.downcase if !it.nil? || issue_type.downcase
        end

        # this method does the actual mapping, as specified
        # in the field_mapping_by_type method
        def map_issue_fields(issue_type, issue)
          mapping_areas = default_issue_field_mapping(issue_type) # asset, vuln, vuln_def

          # then execute the mapping
          out = {}

          ## For each area (asset,vuln,vuln_def) in the mapping
          mapping_areas.each do |area, mapping|
            out[area] = {}

            ## For each item in the mappin
            mapping.each do |map_item|
              target = map_item[:target]
              map_action = map_item[:action]

              ## Perform the requested mapping action
              case map_action
              when "proc" # call a lambda, passing in the whole exposure
                out[area][target] = map_item[:proc].call(issue)
              when "copy" # copy from source data
                out[area][target] = issue[map_item[:source]]
              when "data" # static data
                out[area][target] = map_item[:data]
              end
            end
          end

          ## always set our exposure type... this should save some typing in the mapping file...
          # out["vuln"]["scanner_identifier"] = exposure_type.downcase.gsub("-","_")
          # out["vuln_def"]["scanner_identifier"] = exposure_type.downcase.gsub("-","_")

          out
        end

        def create_kdi_from_issues(max_pages, max_per_page, issue_types, priorities, tags)
          ###
          ### Get the list of business units
          ###
          business_units = @client.business_units
          ###
          ### Get the list of exposure types
          ###
          issue_types = @client.issue_types if issue_types.nil?
          ###
          ### For each exposure type
          ###
          business_units.lazy.sort.each do |bu|
            issue_types.lazy.sort.each do |it|
              # issue_type = snake_case(it)
              unless field_mapping_for_issue_types[it]
                print_error "WARNING! Skipping unmapped issue type: #{it}!"
                next
              end

              print_good "Working on issue type: #{it}!"
              issues = @client.issues(max_pages, max_per_page, it, bu, priorities, tags)
              print_good "Got #{issues.count} issues of type #{it}"

              # skip if we don't have any
              unless issues.count.positive? # skip empty
                print_debug "No issues of type #{it} found!"
                next
              end
              # map fields for those expsures
              print "Mapping #{issues.count} issues"
              result = issues.map do |i|
                map_issue_fields(it, i)
              end
              print_good "Mapped #{result.count} issues"

              # convert to KDI
              fm = Kenna::Toolkit::Data::Mapping::DigiFootprintFindingMapper
              result.each do |r|
                # NORMALIZE
                cvd = fm.get_canonical_vuln_details("Expanse", r["vuln_def"])
                ### Setup basic vuln attributes
                vuln_attributes = r["vuln"]

                ### Set Scores based on what was available in the CVD
                vuln_attributes["scanner_score"] = cvd["scanner_score"] if cvd["scanner_score"]

                vuln_attributes["override_score"] = cvd["override_score"] if cvd["override_score"]

                # Create the vuln
                create_kdi_asset_vuln(r["asset"], vuln_attributes)

                # Create the vuln def
                # print_debug "Creating vuln def from #{cvd}"
                create_kdi_vuln_def(cvd)
              end
            end
            if @assets.size.positive?
              filename = "expanse_kdi_#{bu}.json"
              kdi_upload @output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key
            end
          end
        end

        def map_issue_priority(sev_word)
          case sev_word
          when "Critical"
            10
          when "High"
            8
          when "Medium"
            6
          when "Low"
            3
          end
        end

        ###
        ### This method provides a field mapping for an exposure, giving the caller
        ### the ability to process each field later with the data it has.
        ###
        def default_issue_field_mapping(issue_type)
          {
            "asset" => [
              { action: "copy", source: "ip", target: "ip_address" },
              { action: "proc",
                target: "hostname",
                proc: lambda { |x|
                        temp = x["domain"]
                        temp = temp.gsub("\*", "WILDCARD") unless temp.nil?
                        temp = x["assets"].first["displayName"] unless x["domain"] || x["ip"]
                        temp
                      } },
              { action: "proc",
                target: "tags",
                proc: lambda { |x|
                        temp = ["Expanse"] # always tag as 'Expanse'

                        # Handle legacy businessUnit tag
                        temp << "businessUnit:#{x['businessUnit']['name']}" if x.key?("businessUnit")

                        # Handle new businessUnits (plural) tag
                        if x.key?("businessUnits")
                          x["businessUnits"].each do |bu|
                            temp << bu.fetch("name")
                          end
                        end

                        # Annotations are like tags, add each one
                        if x.key?("annotations")
                          x["annotations"]["tags"].each do |at|
                            temp << at.fetch("name")
                          end
                        end

                        # flatten since we have an array of arrays
                        temp.flatten
                      } }
            ],
            "vuln" => [
              { action: "proc", target: "scanner_identifier", proc: ->(_x) { issue_type.downcase } },
              { action: "proc", target: "created_at", proc: ->(x) { x["initialEvidence"]["timestamp"] } },
              { action: "proc", target: "last_seen_at", proc: ->(x) { x["latestEvidence"]["timestamp"] } },
              { action: "proc", target: "port", proc: ->(x) { (x["portNumber"] || x["initialEvidence"]["portNumber"]).to_i } },
              { action: "proc", target: "details", proc: ->(x) { JSON.pretty_generate(x) } },
              { action: "proc", target: "scanner_score", proc: ->(x) { map_issue_priority(x["priority"]) } },
              { action: "data", target: "scanner_type", data: "Expanse" }
            ],
            "vuln_def" => [
              { action: "data", target: "scanner_type", data: "Expanse" },
              { action: "proc", target: "scanner_identifier", proc: ->(_x) { issue_type.downcase } },
              { action: "data", target: "remediation", data: "Investigate this Issue!" }
            ]
          }
        end
      end
    end
  end
end
