require 'uri'

class TinyStaticServer
  ROOT = File.expand_path('public', __dir__)

  def handle(parser)
    requested = '.' + URI.parse(parser.request_url).path
    respond(requested)
  end

  private

  def send_file_body(file)
    write_headers(File.size(file))
    stream_file_data(file)
  end

  def respond(target)
    full = File.expand_path(target, ROOT)
    return write_not_found unless full.start_with?(ROOT + File::SEPARATOR)
    return send_file_body(full) if File.file?(full)
    write_not_found
  end
end
