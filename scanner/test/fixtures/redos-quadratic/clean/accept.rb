# The same parser with the separator matched first and the whitespace trimmed afterwards.
module AcceptParser
  Q_SEPARATOR = /;\s*q=/

  def self.strip_quality(header)
    if (index = header.index(Q_SEPARATOR))
      header = header[0, index].strip
    end
    header
  end
end
