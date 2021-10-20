# frozen_string_literal: true

module Kenna
  module Toolkit
    module WhitehatSentinel
      class Mapper
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
            triage_state: map_status_to_triage_state(node.fetch(:status))
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
      end
    end
  end
end
