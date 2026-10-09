{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  systemd.services.crm.serviceConfig = { ExecStart = "${pkgs.hello}/bin/hello"; User = "crm-svc"; Group = "crm-svc"; };
}
