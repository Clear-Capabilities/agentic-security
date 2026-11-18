# Synthetic fixture: the same client, dropping credentials when the redirect leaves the origin.
class TinyClient
  def call(verb, url, opts = {})
    response = perform(verb, url, opts)
    if [301, 302, 307].include?(response.status)
      target = response.headers["location"]
      next_url = URI.join(url.to_s, target)
      return call(verb, next_url, without_credentials(opts, url, next_url))
    end
    response
  end

  def without_credentials(opts, from, to)
    return opts if from.scheme == to.scheme && from.host == to.host && from.port == to.port
    opts.merge(headers: opts.fetch(:headers, {}).reject { |k, _| k.to_s.casecmp("authorization").zero? })
  end
end
