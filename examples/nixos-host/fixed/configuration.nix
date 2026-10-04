{ config, pkgs, ... }:
{
  networking.hostName = "edge-1";
  networking.firewall.enable = true;
  networking.firewall.allowedTCPPorts = [ 22 ];

  services.openssh = {
    enable = true;
    settings.PermitRootLogin = "no";
    settings.PasswordAuthentication = false;
  };

  users.users.deploy = {
    isNormalUser = true;
    openssh.authorizedKeys.keys = [ "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForDocsOnlyDoNotUse0000000000 deploy@example" ];
  };

  services.postgresql = {
    enable = true;
    settings.listen_addresses = "localhost";
  };

  systemd.services.report = {
    description = "nightly report";
    serviceConfig = {
      ExecStart = "${pkgs.writeShellScript "report" ''exec report --customer "$REPORT_CUSTOMER"''}";
      DynamicUser = true;
      NoNewPrivileges = true;
      PrivateTmp = true;
    };
  };
}
