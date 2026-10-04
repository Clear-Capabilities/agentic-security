{ config, lib, pkgs, ... }:
{
  programs.bash.shellInit = "echo ${(if config.services.crm.email != "" then "set" else "none")}";
}
