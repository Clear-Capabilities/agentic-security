{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  environment.etc."billing.zip".source = pkgs.fetchzip { url = "https://example.org/billing-v0.zip"; hash = "sha256-wQYkvJLte6gm6xDlf/oAlL5qOXqCReILCsG0gAOsuXg="; };
}
