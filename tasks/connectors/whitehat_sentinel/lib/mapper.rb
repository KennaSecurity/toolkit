# frozen_string_literal: true

module Kenna
  module Toolkit
    module WhitehatSentinel
      class Mapper
        def initialize(scoring_system)
          raise ArgumentError unless %i[advanced legacy].include? scoring_system

          @scoring_system = scoring_system
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
          }
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
      end
    end
  end
end
