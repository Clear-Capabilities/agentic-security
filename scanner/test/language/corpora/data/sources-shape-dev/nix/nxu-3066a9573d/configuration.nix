{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  environment.etc."crm.tar".source = builtins.fetchTarball "https://example.org/crm-u0.tar.gz";
}
