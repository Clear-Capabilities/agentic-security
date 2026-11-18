class FilesController < ApplicationController
  def show
    name = File.basename(params[:name])
    send_file "/srv/files/" + name
  end
end
