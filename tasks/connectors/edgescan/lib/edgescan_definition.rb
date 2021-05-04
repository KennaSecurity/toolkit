# frozen_string_literal: true

module Kenna
  module Toolkit
    module Edgescan
      class EdgescanDefinition
        attr_accessor :data

        def initialize(definition)
          @data = definition
        end

        def to_kenna_definition
          {
            "scanner_type" => "Edgescan",
            "scanner_identifier" => data["id"],
            "name" => data["name"],
            "description" => data["description_src"],
            "solution" => data["remediation_src"],
            "cve_identifiers" => cves,
            "cwe_identifiers" => cwes
          }.compact
        end

        private

        def cves
          data["cves"].empty? ? nil : data["cves"].join(",")
        end

        def cwes
          data["cwes"].empty? ? nil : data["cwes"].join(",")
        end
      end
    end
  end
end
