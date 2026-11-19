class SearchController < ApplicationController
  def index
    term = params[:q]
    render json: { q: term, results: [] }
  end
end
