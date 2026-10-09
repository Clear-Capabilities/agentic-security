{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  environment.systemPackages = [ (pkgs.writeShellApplication {
    name = "billing-ping";
    runtimeInputs = [ pkgs.curl ];
    text = ''curl -fsS ${lib.escapeShellArg cfg.endpoint}/health'';
  }) ];
}
