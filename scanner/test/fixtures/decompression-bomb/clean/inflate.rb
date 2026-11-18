require 'zlib'

class Unpacker
  LIMIT = 8 * 1024 * 1024

  def expand(io)
    gz = Zlib::GzipReader.new(io)
    out = +''
    while (chunk = gz.read(16_384))
      out << chunk
      raise ArgumentError, 'too large' if out.bytesize > LIMIT
    end
    out
  end
end
