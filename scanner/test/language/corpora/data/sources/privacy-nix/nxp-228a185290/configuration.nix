{ config, lib, pkgs, ... }:
{
  programs.bash.shellInit = "echo ${(if config.services.crm.address == "" then "none" else "set")}";
}
