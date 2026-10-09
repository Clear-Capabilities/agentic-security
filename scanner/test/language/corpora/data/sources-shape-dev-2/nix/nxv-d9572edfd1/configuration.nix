{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  systemd.services.billing-fetch.script = "${pkgs.curl}/bin/curl -fsS ${lib.escapeShellArg cfg.url} -o /var/lib/billing/data";
}
