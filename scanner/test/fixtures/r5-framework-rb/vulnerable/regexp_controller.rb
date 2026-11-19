class SearchController < ApplicationController
  def show
    re = Regexp.new(params[:pattern])
    head :ok
  end
end
