class ToolsController < ApplicationController
  def run
    out, status = Open3.capture2("ls " + params[:dir])
    render plain: out
  end
end