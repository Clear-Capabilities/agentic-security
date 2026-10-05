{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  systemd.services.crm = { wantedBy = [ "multi-user.target" ]; serviceConfig = { ExecStart = "${pkgs.hello}/bin/hello"; DynamicUser = true; }; };
}
