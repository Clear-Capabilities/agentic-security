# Independently authored: a header parser that searches with a leading whitespace run.
module AcceptParser
  Q_SEPARATOR = /\s*;\s*q=/

  def self.strip_quality(header)
    if (index = header.index(Q_SEPARATOR))
      header = header[0, index]
    end
    header
  end
end
