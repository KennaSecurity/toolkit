require 'csv'
require 'json'

module Kenna
module Toolkit

  class CsvHelpers
    # Class for manipulating CSV data to other data formats such as json and ruby hashes
    attr_accessor :data, :csv

    def initialize(filepath)
      # Todo: add in optional arg to accept 'string, of, csv, and, not, just, file, input'
      @data = File.read(filepath)
      @csv = CSV.parse(data, headers: true)
    end

    def to_json
      csv.to_json
    end

    def to_hash(sym_keys=false)
      # uses Hash#transform_keys: https://bugs.ruby-lang.org/issues/13583
      csv_hash = csv.map(&:to_h)

      unless sym_keys 
        csv_hash
      else 
        csv_hash.map { |row| row.transform_keys(&:to_sym) }
      end
    end

  end

end
end
