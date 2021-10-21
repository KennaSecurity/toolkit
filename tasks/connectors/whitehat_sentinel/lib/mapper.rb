# frozen_string_literal: true

module Kenna
  module Toolkit
    module WhitehatSentinel
      class Mapper
        def initialize(scoring_system)
          raise ArgumentError unless %i[advanced legacy].include? scoring_system

          @scoring_system = scoring_system
          @tag_hash = {}
          @sanitizer = Sanitize.new(remove_contents: false, parser_options: { max_attributes: -1 })
        end

        def register_asset(node)
          asset = node[:asset]

          @tag_hash[asset[:id]] = tags_for(asset)
        end

        def asset_hash(node, sanitized_url)
          site_id = node[:site].to_i

          {
            application: node[:site_name],
            url: sanitized_url,
            tags: @tag_hash.fetch(site_id, [])
          }
        end

        def finding_hash(node)
          closed_at = Time.parse(node[:closed]) if node[:closed]

          {
            scanner_identifier: node[:id],
            scanner_type: "Whitehat Sentinel",
            created_at: Time.parse(node[:found]),
            last_seen_at: closed_at || Time.now,
            last_fixed_on: closed_at,
            closed_at: closed_at,
            vuln_def_name: node[:class],
            triage_state: map_status_to_triage_state(node.fetch(:status)),
            severity: severity_of(node),
            additional_details: attack_vectors(node)
          }.compact
        end

        private

        def map_status_to_triage_state(status)
          case status.upcase
          when "OPEN"
            "in_progress"
          when "CLOSED"
            "resolved"
          when "ACCEPTED"
            "risk_accepted"
          when "INVALID"
            "not_a_security_issue"
          else
            "new"
          end
        end

        def severity_of(node)
          if @scoring_system == :legacy
            node.fetch(:severity).to_i * 2
          else
            node.fetch(:risk).to_i * 2
          end
        end

        def tags_for(asset)
          [asset[:tags],
           asset[:label],
           asset[:asset_owner_name],
           asset[:custom_asset_id]].flatten.compact.reject(&:empty?)
        end

        def attack_vectors(node)
          return {} if node[:attack_vectors].empty?

          vector = node[:attack_vectors].first

          {
            request_method: vector[:request][:method],
            request_url: vector[:request][:url],
            request_body: vector[:request][:body],
            request_param_name: vector[:request][:param_name],
            request_param_value: vector[:request][:param_value],
            request_headers: combine_headers(vector[:request][:headers]),
            response_status: vector[:response][:status],
            response_headers: combine_headers(vector[:response][:headers])
          }.compact.transform_values { |v| sanitize(v) }
        end

        def combine_headers(headers)
          return nil if headers.nil? || headers.empty?

          headers.map { |header| "#{header[:name]}=#{header[:value]}" }.join(" ")
        end

        def sanitize(string)
          @sanitizer.fragment(string)
        end
      end
    end
  end
end
