{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  systemd.services.billing.serviceConfig = { ExecStart = "${pkgs.hello}/bin/hello"; User = "billing-svc"; NoNewPrivileges = true; ProtectSystem = "strict"; };
}
