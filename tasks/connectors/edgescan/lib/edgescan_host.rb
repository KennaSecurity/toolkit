# frozen_string_literal: true

module Kenna
  module Toolkit
    module Edgescan
      class EdgescanHost
        attr_accessor :data

        def initialize(asset, host)
          @asset = asset
          @data = host
        end

        def id
          data["id"]
        end

        def location
          data["location"]
        end

        def hostname
          data["hostnames"].join(", ")
        end

        def os_name
          data["os_name"]
        end

        def to_corresponding_kenna_asset
          {
            "external_id" => external_asset_id,
            "tags" => asset.tags,
            "ip" => host.location,
            "hostname" => host.hostname,
            "os" => host.os_name
          }
        end

        private

        def external_asset_id
          "ES#{asset.id} #{location}"
        end
      end
    end
  end
end
