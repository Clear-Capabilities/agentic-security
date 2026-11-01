{ config, lib, pkgs, ... }:
let
  cfg = config.services.intranet-portal;
in
{
  options.services.intranet-portal = {
    enable = lib.mkEnableOption "the staff portal";
    domain = lib.mkOption { type = lib.types.str; default = "portal.example.internal"; };
  };

  config = lib.mkIf cfg.enable {
    services.httpd = {
      enable = true;
      adminAddr = "ops@example.com";
      virtualHosts.${cfg.domain} = {
        documentRoot = "/srv/portal";
        addSSL = true;
        sslServerCert = ./certs/portal.crt;
        sslServerKey = ./certs/portal.key;
      };
    };
    networking.firewall.allowedTCPPorts = [ 443 ];
  };
}
