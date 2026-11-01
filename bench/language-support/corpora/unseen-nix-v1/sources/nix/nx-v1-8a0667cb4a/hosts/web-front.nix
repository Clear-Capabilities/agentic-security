{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "web-front";

  networking.firewall.enable = false;

  services.caddy = {
    enable = true;
    virtualHosts."www.example.org".extraConfig = ''
      root * /srv/www
      file_server
    '';
  };

  services.prometheus.exporters.node = {
    enable = true;
    listenAddress = "127.0.0.1";
  };
}
