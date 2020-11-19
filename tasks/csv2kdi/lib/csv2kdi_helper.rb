module Kenna
  module Toolkit
    module Csv2kdihelper
      def generate_kdi_file
        { skip_autoclose: ($skip_autoclose.eql?('true') ? true : false), assets: $assets.uniq, vuln_defs: $vuln_defs.uniq }
      end

      def create_asset(file, ip_address, mac_address, hostname, ec2, netbios, url, fqdn, external_id, database, application, tags, owner, os, os_version, priority)
        tmpassets = []
        success = true

        # this case statement will check for dup assets based on the main locator as declared in the options input file
        # comment out the entire block if you want all deduplicaton to happen in Kenna

        case $map_locator
        when "ip_address"
          return success unless $assets.select { |a| a[:ip_address] == ip_address }.empty?
        when "hostname"
          return success unless $assets.select { |a| a[:hostname] == hostname }.empty?
        when "file"
          return success unless $assets.select { |a| a[:file] == file }.empty?
        when "mac_address"
          return success unless $assets.select { |a| a[:mac_address] == mac_address }.empty?
        when "netbios"
          return success unless $assets.select { |a| a[:netbios] == netbios }.empty?
        when "ec2"
          return success unless $assets.select { |a| a[:ec2] == ec2 }.empty?
        when "fqdn"
          return success unless $assets.select { |a| a[:fqdn] == fqdn }.empty?
        when "external_id"
          return success unless $assets.select { |a| a[:external_id] == external_id }.empty?
        when "database"
          return success unless $assets.select { |a| a[:database] == database }.empty?
        when "url"
          return success unless $assets.select { |a| a[:url] == url }.empty?
        else
          puts "Error: main locator not provided" if @debug
          success = false

        end

        tmpassets << { file: file.to_s } unless file.nil? || file.empty?
        tmpassets << { ip_address: ip_address } unless ip_address.nil? || ip_address.empty?
        tmpassets << { mac_address: mac_address } unless mac_address.nil? || mac_address.empty?
        tmpassets << { hostname: hostname } unless hostname.nil? || hostname.empty?
        tmpassets << { ec2: ec2.to_s } unless ec2.nil? || ec2.empty?
        tmpassets << { netbios: netbios.to_s } unless netbios.nil? || netbios.empty?
        tmpassets << { url: url.to_s } unless url.nil? || url.empty?
        tmpassets << { fqdn: fqdn.to_s } unless fqdn.nil? || fqdn.empty?
        tmpassets << { external_id: external_id.to_s } unless external_id.nil? || external_id.empty?
        tmpassets << { database: database.to_s } unless database.nil? || database.empty?
        tmpassets << { application: application.to_s } unless application.nil? || application.empty?
        tmpassets << { tags: tags } unless tags.nil? || tags.empty?
        tmpassets << { owner: owner.to_s } unless owner.nil? || owner.empty?
        tmpassets << { os: os.to_s } unless os.nil? || os.empty?
        tmpassets << { os_version: os_version.to_s } unless os_version.nil? || os_version.to_s.empty?
        tmpassets << { priority: priority } unless priority.nil? || priority.to_s.empty?
        tmpassets << { vulns: [] }

        success = false if file.to_s.empty? && ip_address.to_s.empty? && mac_address.to_s.empty? && hostname.to_s.empty? && ec2.to_s.empty? && netbios.to_s.empty? && url.to_s.empty? && database.to_s.empty? && external_id.to_s.empty? && fqdn.to_s.empty? && application.to_s.empty?

        $assets << tmpassets.reduce(&:merge) if success

        return success
      end

      def create_asset_vuln(hostname, ip_address, file, mac_address, netbios, url, ec2, fqdn, external_id, database, scanner_type, scanner_id, details, created, scanner_score, last_fixed,
                            last_seen, status, closed, port)

        # find the asset
        case $map_locator
        when "ip_address"
          asset = $assets.select { |a| a[:ip_address] == ip_address }.first
        when "hostname"
          asset = $assets.select { |a| a[:hostname] == hostname }.first
        when "file"
          asset = $assets.select { |a| a[:file] == file }.first
        when "mac_address"
          asset = $assets.select { |a| a[:mac_address] == mac_address }.first
        when "netbios"
          asset = $assets.select { |a| a[:netbios] == netbios }.first
        when "url"
          asset = $assets.select { |a| a[:url] == url }.first
        when "ec2"
          asset = $assets.select { |a| a[:ec2] == ec2 }.first
        when "fqdn"
          asset = $assets.select { |a| a[:fqdn] == fqdn }.first
        when "external_id"
          asset = $assets.select { |a| a[:external_id] == external_id }.first
        when "database"
          asset = $assets.select { |a| a[:database] == database }.first
        else
          "Error: main locator not provided" if @debug
        end

        puts "Unknown asset, can't associate a vuln!" unless asset
        return unless asset

        # associate the asset
        assetvulns = []
        assetvulns << { scanner_type: scanner_type.to_s, scanner_identifier: scanner_id.to_s, }
        assetvulns << { details: details.to_s } unless details.nil?
        assetvulns << { created_at: created.to_s } unless created.nil?
        assetvulns << { scanner_score: scanner_score } unless scanner_score.nil? || scanner_score.zero?
        assetvulns << { last_fixed_on: last_fixed.to_s } unless last_fixed.nil?
        assetvulns << { last_seen_at: last_seen.to_s } unless last_seen.nil?
        assetvulns << { closed_at: closed.to_s } unless closed.nil?
        assetvulns << { port: port, } unless port.nil?
        assetvulns << { status: status.to_s }

        asset[:vulns] << assetvulns.reduce(&:merge)
      end

      def create_vuln_def(scanner_type, scanner_id, cve_id, wasc_id, cwe_id, name, description, solution)
        vuln_def = []
        vuln_def << { scanner_type: scanner_type.to_s, scanner_identifier: scanner_id.to_s, }
        vuln_def << { cve_identifiers: cve_id.to_s } unless cve_id.nil? || cve_id.empty?
        vuln_def << { wasc_identifiers: wasc_id.to_s } unless wasc_id.nil? || wasc_id.empty?
        vuln_def << { cwe_identifiers: cwe_id.to_s } unless cwe_id.nil? || cwe_id.empty?
        vuln_def << { name: name.to_s } unless name.nil? || name.empty?
        vuln_def << { description: description.to_s } unless description.nil? || description.empty?
        vuln_def << { solution: solution.to_s } unless solution.nil? || solution.empty?

        $vuln_defs << vuln_def.reduce(&:merge)
      end
    end
  end
end
