class CalcController < ApplicationController
  OPERATIONS = { "sum" => :sum, "max" => :max }
  def show
    op = OPERATIONS.fetch(params[:op], :sum)
    head :ok
  end
end
