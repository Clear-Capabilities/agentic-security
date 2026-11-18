# Synthetic fixture: a missing or empty key is refused before signing.
class TokenSigner
  def sign(payload, key)
    raise ArgumentError, 'signing key required' if key.nil? || key.empty?
    OpenSSL::HMAC.hexdigest('SHA256', key, payload)
  end
end
