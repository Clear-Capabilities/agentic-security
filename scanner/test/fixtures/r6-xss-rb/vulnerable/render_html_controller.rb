class SearchController < ApplicationController
  def index
    term = params[:q]
    render html: "<p>No results for #{term}</p>".html_safe
  end
end
