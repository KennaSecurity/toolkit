# frozen_string_literal: true

module Kenna
  module Toolkit
    module WhitehatSentinel
      class Mapper
        def initialize(scoring_system)
          raise ArgumentError unless %i[advanced legacy].include? scoring_system

          @scoring_system = scoring_system
          @tag_hash = {}
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
            severity: severity_of(node)
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
      end
    end
  end
end
