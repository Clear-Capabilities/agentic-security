require 'uri'

class TinyStaticServer
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
    return send_file_body(target) if File.file?(target)
    write_not_found
  end
end
