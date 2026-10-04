{ config, lib, pkgs, ... }:
let
  appName = "wiki1";
  appPort = 8183;
in
{
  systemd.services.${appName}.description = "wiki service 1";
  networking.hostName = appName;
  services.nginx.enable = true;
  services.nginx.virtualHosts."wiki.example.org".forceSSL = true;
}
