class FilesController < ApplicationController
  def show
    send_file "/srv/files/" + params[:name]
  end
end