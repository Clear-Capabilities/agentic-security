class CalcController < ApplicationController
  def show
    result = instance_eval(params[:expr])
    head :ok
  end
end
