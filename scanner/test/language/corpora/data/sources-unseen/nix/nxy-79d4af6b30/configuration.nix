{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  environment.etc."billing.src".source = builtins.fetchGit { url = "https://example.org/billing.git"; ref = "main"; };
}
