{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  environment.etc."crm.git".source = builtins.fetchGit { url = "https://example.org/crm.git"; ref = "master"; };
}
