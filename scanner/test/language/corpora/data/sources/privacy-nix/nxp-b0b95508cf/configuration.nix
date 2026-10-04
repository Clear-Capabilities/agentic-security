{ config, lib, pkgs, ... }:
{
  programs.bash.shellInit = "echo ${toString (builtins.stringLength config.services.crm.cardNo + 0)}";
}
