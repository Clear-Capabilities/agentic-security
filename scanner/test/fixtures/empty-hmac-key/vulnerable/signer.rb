# Synthetic fixture: a missing key silently becomes the empty string.
class TokenSigner
  def sign(payload, key)
    key ||= ''
    OpenSSL::HMAC.hexdigest('SHA256', key, payload)
  end
end
