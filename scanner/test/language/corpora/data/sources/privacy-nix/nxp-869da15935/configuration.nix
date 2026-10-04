{ config, lib, pkgs, ... }:
{
  programs.bash.shellInit = "echo ${builtins.hashString "sha256" config.services.crm.ssn}";
}
