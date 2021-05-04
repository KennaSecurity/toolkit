# frozen_string_literal: true

module Kenna
  module Toolkit
    module Edgescan
      class EdgescanAsset
        attr_accessor :data, :vulnerabilities

        def initialize(asset, vulnerabilities)
          @data = asset
          @vulnerabilities = vulnerabilities.map { |vulnerability| EdgescanVulnerability.new(self, vulnerability) }
        end

        def id
          data["id"]
        end

        def tags
          data["tags"]
        end

        def application_id
          "#{data['name']} (ES#{id})"
        end

        def location_specifiers
          @location_specifiers ||= @data["location_specifiers"].map do |specifier|
            EdgescanLocationSpecifier.new(self, specifier)
          end
        end

        def find_location_specifier(specifier_id, location)
          location_specifiers.find { |specifier| specifier.id == specifier_id } ||
            location_specifiers.find { |specifier| specifier.location == location }
        end

        # Converts an Edgescan asset into Kenna friendly ones
        #
        # Edgescan and Kenna assets don't map one to one. A Kenna asset is more like an Edgescan
        # location specifier. Because of that, one Edgescan asset usually gets turned into multiple
        # Kenna assets.
        #
        # This will:
        # - Create Kenna assets based on Edgescan location specifiers
        # - Go through the vulnerabilites and if some of them don't have a matching Edgescan
        #   location specifier create Kenna assets for them
        # - Go through the existing assets on Kenna and mark ones that are now redundant for deletion
        def to_kenna_assets(existing_kenna_assets)
          to_create = kenna_assets_to_create
          to_remove = kenna_assets_to_remove(existing_kenna_assets, to_create)

          to_create + to_remove
        end

        private

        def kenna_assets_to_create
          location_specifiers_as_kenna_assets +
            vulnerabilities_without_location_specifiers_as_kenna_assets
        end

        def location_specifiers_as_kenna_assets
          location_specifiers.map(&:to_kenna_asset)
        end

        def vulnerabilities_without_location_specifiers_as_kenna_assets
          vulnerabilities.reject(&:matching_location_specifier).map(&:to_corresponding_kenna_asset)
        end

        def kenna_assets_to_remove(existing_kenna_assets, to_create)
          existing_ids = existing_kenna_assets.map { |asset| asset["external_id"] }
          creating_ids = to_create.map { |asset| asset["external_id"] }

          redundant_ids = existing_ids - creating_ids

          redundant_ids.map { |id| { "external_id" => id, "application" => application_id } }
        end
      end
    end
  end
end
