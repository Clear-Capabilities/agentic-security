class ImportController < ApplicationController
  def create
    data = File.read("/srv/import/latest.csv")
    head :ok
  end
end
