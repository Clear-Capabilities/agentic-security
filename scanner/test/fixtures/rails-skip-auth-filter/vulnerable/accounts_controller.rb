# Synthetic fixture: per-action levels are declared, but the filter enforcing them is skipped for every action.
class AccountsController < ApplicationController
  skip_before_action :authenticate_for_action
  before_action :load_account, only: [:show, :reset_password]

  action_auth_level :index, :member
  def index
    @accounts = Account.visible_to(current_user)
  end

  action_auth_level :show, :member
  def show; end

  def reset_password
    @account.update!(password: params[:password])
  end
end
