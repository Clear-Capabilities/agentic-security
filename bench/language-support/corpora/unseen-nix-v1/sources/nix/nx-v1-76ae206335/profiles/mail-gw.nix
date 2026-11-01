{ config, lib, pkgs, ... }:
let
  fqdn = "mail-gw.example.org";
in
{
  services.postfix = {
    enable = true;
    hostname = fqdn;
    domain = "example.org";
    sslCert = "/var/lib/acme/${fqdn}/fullchain.pem";
    sslKey = "/var/lib/acme/${fqdn}/key.pem";
    config = {
      smtpd_tls_security_level = "may";
      smtpd_tls_mandatory_protocols = ">=TLSv1.2";
      smtpd_tls_loglevel = "1";
    };
  };

  networking.firewall.allowedTCPPorts = [ 25 587 ];
}
