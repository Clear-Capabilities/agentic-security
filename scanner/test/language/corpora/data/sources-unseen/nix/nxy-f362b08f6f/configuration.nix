{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  environment.systemPackages = [ (pkgs.writeShellApplication {
    name = "crm-ping";
    runtimeInputs = [ pkgs.curl ];
    text = ''curl -fsS ${cfg.endpoint}/health'';
  }) ];
}
