{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  systemd.services.billing = { wantedBy = [ "multi-user.target" ]; serviceConfig = { ExecStart = "${pkgs.hello}/bin/hello"; User = "root"; }; };
}
