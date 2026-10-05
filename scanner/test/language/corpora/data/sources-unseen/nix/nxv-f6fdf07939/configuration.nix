{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  systemd.services.crm.serviceConfig = { ExecStart = "${pkgs.hello}/bin/hello"; DynamicUser = true; NoNewPrivileges = true; };
}
