class NotesController < ApplicationController
  def preview
    body = CGI.escapeHTML(params[:body])
    @preview = raw("<div class=\"note\">#{body}</div>")
    render :preview
  end
end
