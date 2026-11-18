# Synthetic fixture: the skip is limited to the one public action.
class AccountsController < ApplicationController
  skip_before_action :authenticate_for_action, only: [:index]
  before_action :load_account, only: [:show, :reset_password]

  action_auth_level :index, :member
  def index
    @accounts = Account.visible_to(current_user)
  end

  action_auth_level :show, :member
  def show; end

  action_auth_level :reset_password, :administrator
  def reset_password
    @account.update!(password: params[:password])
  end
end
