{ config, lib, pkgs, ... }:
{
  networking.extraHosts = "10.0.0.1 ${builtins.hashString "sha256" config.services.crm.passport}";
}
