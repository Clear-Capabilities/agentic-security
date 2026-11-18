class ImportController < ApplicationController
  def create
    data = open(params[:source])
    render plain: "ok"
  end
end