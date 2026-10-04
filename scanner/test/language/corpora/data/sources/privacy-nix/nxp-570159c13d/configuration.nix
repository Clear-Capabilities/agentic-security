{ config, lib, pkgs, ... }:
{
  programs.bash.shellInit = "echo ${(if config.services.crm.ipAddress != "" then "set" else "none")}";
}
