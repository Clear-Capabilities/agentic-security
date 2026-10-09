{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  environment.etc."crm.src".source = builtins.fetchGit { url = "https://example.org/crm.git"; rev = "0123456789abcdef0123456789abcdef01234567"; };
}
