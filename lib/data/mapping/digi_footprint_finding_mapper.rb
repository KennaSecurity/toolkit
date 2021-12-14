# frozen_string_literal: true

module Kenna
  module Toolkit
    module Data
      module Mapping
        class DigiFootprintFindingMapper
          def initialize(output_directory, input_directory = "", mapping_file = "")
            @output_dir = output_directory
            @missing_mappings = Set.new
            @input_directory = input_directory
            @mapping_file = mapping_file
            validate_options
          end

          def get_canonical_vuln_details(orig_source, specific_details, description = "", remediation = "")
            ###
            ### Transform the identifier from the upstream source downcasing and
            ### then removing spaces and dashes in favor of an underscore
            ###
            orig_vuln_id = (specific_details["scanner_identifier"]).to_s.downcase.tr(" ", "_").tr("-", "_")
            # orig_description = specific_details["description"]
            # orig_recommendation = specific_details["recommendation"]
            out = {}
            done = false
            # Do the mapping
            ###################
            map_data.each do |map|
              break if done

              map[:matches].each do |match|
                break if done

                next unless match[:source] == orig_source

                next unless match[:vuln_id]&.match?(orig_vuln_id)

                out = {
                  scanner_type: orig_source,
                  scanner_identifier: orig_vuln_id,
                  source: "#{orig_source} (Kenna Normalized)",
                  scanner_score: (map[:score] / 10).to_i,
                  override_score: (map[:score]).to_i,
                  name: map[:name],
                  description: "#{map[:description]}\n\n #{description}".strip,
                  recommendation: "#{map[:recommendation]}\n\n #{remediation}".strip
                }
                out.compact!
                out = out.stringify_keys
                done = true
              end
            end
            # we didnt map it, so just pass it back
            if out.empty?
              print_debug "WARNING! Unable to map canonical vuln for type: #{orig_vuln_id}"
              @missing_mappings << [orig_vuln_id, orig_source]
              write_file(@output_dir, "missing_mappings_#{DateTime.now.strftime('%Y-%m-%d')}.csv", @missing_mappings.map(&:to_csv).join) unless @missing_mappings.nil?
              out = {
                scanner_identifier: orig_vuln_id,
                scanner_type: orig_source,
                source: orig_source,
                name: orig_vuln_id
              }.stringify_keys.merge(specific_details)
            end
            out
          end

          private

          def validate_options
            raise "Missing required input_directory parameter" unless @input_directory
            raise "Missing required mapping_file parameter" unless @mapping_file
            raise "Mappings file not found: #{mapping_file_path}" unless File.exist?(mapping_file_path)
          end

          def mapping_file_path
            "#{@input_directory}/#{@mapping_file}"
          end

          def map_data
            @map_data ||= build_mapping_data
          end

          def build_mapping_data
            mappings = []
            rows = CSV.parse(File.open(mapping_file_path, "r:iso-8859-1:utf-8", &:read), headers: true)
            definitions = rows.select { |row| row["type"] == "definition" }
            definitions.each do |row|
              mapping = {
                name: row[1],
                cwe: row[2],
                score: row[3].to_i,
                description: row[4],
                recommendation: row[5]
              }
              mappings << mapping
            end
            mappings_by_name = mappings.index_by { |m| m[:name] }
            matchers = rows.select { |row| row["type"] == "match" }
            matchers.each do |row|
              mapping = mappings_by_name[row["name"]]
              raise "Invalid mapping file. Matcher references non existent definition named: #{row[:name]}." unless mapping

              matcher = {
                source: row[2],
                vuln_id: row[3]
              }
              (mapping[:matches] ||= []) << matcher
            end
            mappings
          end
        end
      end
    end
  end
end
