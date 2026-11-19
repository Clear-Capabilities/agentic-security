class NotesController < ApplicationController
  def preview
    body = params[:body]
    @preview = raw("<div class=\"note\">#{body}</div>")
    render :preview
  end
end
