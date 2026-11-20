class FeedsController < ApplicationController
  def create
    doc = JSON.parse(request.body.read, max_nesting: false)
    render json: doc
  end

  def import
    xml = Nokogiri::XML(params[:feed]) { |config| config.huge }
    render plain: xml.root.name
  end
end
