class SearchController < ApplicationController
  def show
    re = Regexp.new(Regexp.escape(params[:pattern]))
    head :ok
  end
end
