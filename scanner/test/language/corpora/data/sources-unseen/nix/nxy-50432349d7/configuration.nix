{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  systemd.services.billing.serviceConfig = { ExecStart = "${pkgs.hello}/bin/hello"; Restart = "always"; };
}
