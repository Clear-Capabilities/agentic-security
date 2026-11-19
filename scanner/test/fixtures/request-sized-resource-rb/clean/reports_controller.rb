class ReportsController < ApplicationController
  MAX_ROWS = 1000

  def padding
    width = params[:width].to_i.clamp(0, 200)
    render plain: ' ' * width
  end

  def rows
    rows = params[:rows].to_i
    return head(:bad_request) if rows > MAX_ROWS
    out = Array.new(rows)
    rows.times { |i| out[i] = i }
    render json: out
  end
end
