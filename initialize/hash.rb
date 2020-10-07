class Hash
  
  # https://stackoverflow.com/questions/9381553/ruby-merge-nested-hash
  def deep_merge(other)
    merger = proc { |key, v1, v2| Hash === v1 && Hash === v2 ? v1.merge(v2, &merger) : Array === v1 && Array === v2 ? v1 | v2 : [:undefined, nil, :nil].include?(v2) ? v1 : v2 }
    self.merge(other.to_h, &merger)
  end

  # via https://stackoverflow.com/a/25835016/2257038
  def stringify_keys
    h = self.map do |k,v|
      v_str = if v.instance_of? Hash
                v.stringify_keys
              else
                v
              end

      [k.to_s, v_str]
    end
    Hash[h]
  end

  # via https://stackoverflow.com/a/25835016/2257038
  def symbolize_keys
    h = self.map do |k,v|
      v_sym = if v.instance_of? Hash
                v.symbol_keys
              else
                v
              end

      [k.to_sym, v_sym]
    end
    Hash[h]
  end

  # recursively remove nil keys
  def compact(opts={})
    inject({}) do |new_hash, (k,v)|
      if !v.nil?
        new_hash[k] = opts[:recurse] && v.class == Hash ? v.compact(opts) : v
      end
      new_hash
    end
  end


  # Returns a hash that includes everything but the given keys.
  #   hash = { a: true, b: false, c: nil}
  #   hash.except(:c) # => { a: true, b: false}
  #   hash # => { a: true, b: false, c: nil}
  #
  # This is useful for limiting a set of parameters to everything but a few known toggles:
  #   @person.update(params[:person].except(:admin))
  def except(*keys)
    dup.except!(*keys)
  end

  # Replaces the hash without the given keys.
  #   hash = { a: true, b: false, c: nil}
  #   hash.except!(:c) # => { a: true, b: false}
  #   hash # => { a: true, b: false }
  def except!(*keys)
    keys.each { |key| delete(key) }
    self
  end


end