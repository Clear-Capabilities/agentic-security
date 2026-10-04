{ config, lib, pkgs, ... }:
{
  programs.bash.shellInit = "echo ${(if config.services.crm.diagnosis == "" then "none" else "set")}";
}
