class ToolsController < ApplicationController
  def run
    out, status = Open3.capture2("ls", params[:dir])
    head :ok
  end
end