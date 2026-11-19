class CardsController < ApplicationController
  include ActionView::Helpers::TagHelper

  def show
    caption = params[:caption]
    @card = content_tag(:div, caption, { class: "card" }, false)
    render :show
  end
end
