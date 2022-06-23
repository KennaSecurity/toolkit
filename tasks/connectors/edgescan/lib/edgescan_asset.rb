# frozen_string_literal: true

module Kenna
  module Toolkit
    module Edgescan
      class EdgescanAsset
        attr_accessor :data, :vulnerabilities, :hosts

        def initialize(asset, vulnerabilities, hosts)
          @data = asset
          @vulnerabilities = vulnerabilities.map { |vulnerability| EdgescanVulnerability.new(self, vulnerability) }
          @hosts = hosts.map { |host| EdgescanHost.new(self, host) }
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

        def application?
          data["type"] == "app"
        end

        # Converts an Edgescan asset into Kenna friendly ones
        #
        # This will:
        # - Create Kenna assets based on Edgescan hosts
        # - If a matching host is not found an asset will be created from the vulnerability data
        def to_kenna_assets
          vulnerabilities.each_with_object([]) do |vulnerability, assets|
            host = find_host(vulnerability.location)
            asset = host ? host.to_corresponding_kenna_asset : vulnerability.to_corresponding_kenna_asset
            assets << asset
          end
        end

        private

        def find_host(location)
          host = hosts.find { |h| h.location == location }
          return host unless host.nil?

          host = hosts.find { |h| h.hostnames.each { |hostname| location.include?(hostname) } }
          return host unless host.nil?

          nil
        end
      end
    end
  end
end
