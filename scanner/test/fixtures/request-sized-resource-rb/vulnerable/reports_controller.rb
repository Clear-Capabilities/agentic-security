class ReportsController < ApplicationController
  def padding
    width = params[:width].to_i
    render plain: ' ' * width
  end

  def rows
    rows = params[:rows].to_i
    out = Array.new(rows)
    rows.times { |i| out[i] = i }
    render json: out
  end
end
