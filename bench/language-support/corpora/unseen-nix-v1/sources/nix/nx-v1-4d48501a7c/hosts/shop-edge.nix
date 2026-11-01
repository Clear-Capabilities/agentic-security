{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "shop-edge";

  security.acme.acceptTerms = true;
  security.acme.defaults.email = "ops@example.com";

  services.nginx = {
    enable = true;
    recommendedProxySettings = true;
    virtualHosts."shop.example.com" = {
      forceSSL = true;
      enableACME = true;
      root = "/srv/shop/public";
      locations."/api/".proxyPass = "http://127.0.0.1:8081/";
    };
  };

  networking.firewall.allowedTCPPorts = [ 80 443 ];
}
