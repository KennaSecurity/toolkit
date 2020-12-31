module Kenna
  module Toolkit
    module SynackHelper

      def create_asset(exploitable_location, application, assets)

        tmpassets = []

        url = nil
        file = nil
        ip_address = nil
        location_value = exploitable_location[:value]
        location_address = exploitable_location[:address]
        application_value = application.nil? ? '' : application

        asset = find_asset assets, exploitable_location

        return [] unless asset.nil?

        case exploitable_location[:type]
          when 'url'
            url = location_value
          when 'other', 'app-location'
            application_value = location_value.nil? ? application_value : "#{application_value} #{location_value}".strip
          when 'file'
            file = location_value
          when 'ip'
            ip_address = location_address
          else
            return []
        end

        tmpassets << {url: "#{url}"} unless url.nil? || url.empty?
        tmpassets << {file: "#{file}"} unless file.nil? || file.empty?
        tmpassets << {ip_address: "#{ip_address}"} unless ip_address.nil? || ip_address.empty?
        tmpassets << {application: "#{application_value}"} unless application_value.nil? || application_value.empty?
        tmpassets << {vulns: []} unless tmpassets.length == 0

        tmpassets.reduce(&:merge) unless tmpassets.length == 0
      end


      def find_asset(assets, exploitable_location)

        location_value = exploitable_location[:value]
        location_address = exploitable_location[:address]
        case exploitable_location[:type]
          when 'url'
            asset = assets.select { |a| a[:url] == location_value }.first
          when 'other', 'app-location'
            asset = assets.select { |a| a[:application].to_s.end_with?(location_value) }.first
          when 'file'
            asset = assets.select { |a| a[:file] == location_value }.first
          when 'ip'
            asset = assets.select { |a| a[:ip_address] == location_address }.first
        end
        return asset
      end

      def create_asset_vuln(assets, exploitable_location, scanner_type, scanner_id, last_seen, last_fixed_on, created, scanner_score, details, closed, status)

        asset = find_asset assets, exploitable_location
        puts "Unknown asset, can't associate a vuln!" unless asset
        return unless asset

        # associate the asset
        assetvulns = []

        assetvulns << {scanner_type: "#{scanner_type}", scanner_identifier: "#{scanner_id}"}
        assetvulns << {last_seen_at: "#{last_seen}"} unless last_seen.nil?
        assetvulns << {last_fixed_on: "#{last_fixed_on}"} unless last_fixed_on.nil?
        assetvulns << {created_at: "#{created}"} unless created.nil?
        assetvulns << {scanner_score: scanner_score} unless scanner_score.nil? || scanner_score == 0
        assetvulns << {details: "#{details}"} unless details.nil?
        assetvulns << {closed_at: "#{closed}"} unless closed.nil?
        assetvulns << {status: "#{status}"}
        assetvulns << {port: exploitable_location[:port]} unless exploitable_location[:port].nil?

        asset[:vulns] << assetvulns.reduce(&:merge)

      end
      def get_synack_vulnerabilities(synack_base_url, token, cert_file_path)

        endpoint = "#{synack_base_url}/v1/vulnerabilities"

        response = RestClient::Request.new(
            :method => :get,
            :url => endpoint,
            :headers => {:accept => :json, :content_type => :json, :Authorization => "Bearer #{token}"},
            :verify_ssl => false
        ).execute

        result = JSON.parse(response.body)

      end
    end
  end
end