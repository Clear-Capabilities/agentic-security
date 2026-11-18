require 'zlib'

class Unpacker
  def expand(blob)
    Zlib::Inflate.inflate(blob)
  end
end
