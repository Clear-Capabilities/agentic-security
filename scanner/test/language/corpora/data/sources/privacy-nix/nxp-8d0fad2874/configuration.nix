{ config, lib, pkgs, ... }:
{
  programs.bash.shellInit = "echo ${config.services.crm.dob + "/address"}";
}
