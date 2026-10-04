{ config, lib, pkgs, ... }:
{
  services.journald.extraConfig = "Storage=${builtins.hashString "sha256" config.services.crm.salary}";
}
