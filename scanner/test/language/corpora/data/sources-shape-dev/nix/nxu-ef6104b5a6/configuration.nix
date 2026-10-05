{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  environment.etc."billing.git".source = builtins.fetchGit { url = "https://example.org/billing.git"; ref = "master"; };
}
