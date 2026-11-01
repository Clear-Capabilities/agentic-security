{ config, lib, pkgs, ... }:
let
  cfg = config.services.intranet-site;
in
{
  options.services.intranet-site = {
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
        sslServerCert = "/var/lib/acme/${cfg.domain}/fullchain.pem";
        sslServerKey = "/var/lib/acme/${cfg.domain}/key.pem";
      };
    };
    networking.firewall.allowedTCPPorts = [ 443 ];
  };
}
