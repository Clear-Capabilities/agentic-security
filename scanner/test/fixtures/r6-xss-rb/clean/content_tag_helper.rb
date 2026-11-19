class CardsController < ApplicationController
  include ActionView::Helpers::TagHelper

  def show
    caption = params[:caption]
    @card = content_tag(:div, caption, class: "card")
    render :show
  end
end
