class PagesController < ApplicationController
  def show
    title = params[:title]
    render inline: "<h1>#{title}</h1>"
  end
end
