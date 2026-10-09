{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  systemd.services.crm-fetch.script = "${pkgs.curl}/bin/curl -fsS ${lib.escapeShellArg cfg.url} -o /var/lib/crm/data";
}
