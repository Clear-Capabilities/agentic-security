{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  environment.etc."crm.tar".source = builtins.fetchTarball "https://example.org/crm-v0.tar.gz";
}
