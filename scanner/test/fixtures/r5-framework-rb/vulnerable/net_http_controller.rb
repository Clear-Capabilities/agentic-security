class ProxyController < ApplicationController
  def show
    body = Net::HTTP.get(URI(params[:url]))
    render plain: body
  end
end