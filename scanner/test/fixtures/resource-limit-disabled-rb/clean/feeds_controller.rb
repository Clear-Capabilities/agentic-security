class FeedsController < ApplicationController
  def create
    doc = JSON.parse(request.body.read, max_nesting: 20)
    render json: doc
  end

  def import
    xml = Nokogiri::XML(params[:feed]) { |config| config.strict }
    render plain: xml.root.name
  end
end
