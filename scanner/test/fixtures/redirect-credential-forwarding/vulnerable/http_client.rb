# Synthetic fixture: a client that follows redirects itself and re-sends the caller's options unchanged.
class TinyClient
  def call(verb, url, opts = {})
    response = perform(verb, url, opts)
    if [301, 302, 307].include?(response.status)
      target = response.headers["location"]
      next_url = URI.join(url.to_s, target)
      return call(verb, next_url, opts)
    end
    response
  end
end
