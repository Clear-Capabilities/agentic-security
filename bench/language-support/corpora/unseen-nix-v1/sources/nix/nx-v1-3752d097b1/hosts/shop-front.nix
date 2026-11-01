{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "shop-front";

  services.nginx = {
    enable = true;
    recommendedProxySettings = true;
    virtualHosts."shop.example.com" = {
      forceSSL = false;
      root = "/srv/shop/public";
      locations."/api/".proxyPass = "http://127.0.0.1:8081/";
    };
  };

  networking.firewall.allowedTCPPorts = [ 80 443 ];
}
