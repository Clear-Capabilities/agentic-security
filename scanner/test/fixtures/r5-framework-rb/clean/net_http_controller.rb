class ProxyController < ApplicationController
  def show
    body = Net::HTTP.get(URI("https://api.internal.test/status"))
    render plain: body
  end
end