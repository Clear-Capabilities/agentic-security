{ config, pkgs, ... }:
{
  networking.hostName = "edge-1";
  networking.firewall.enable = false;

  services.openssh = {
    enable = true;
    settings.PermitRootLogin = "yes";
    settings.PasswordAuthentication = true;
  };

  users.users.deploy = {
    isNormalUser = true;
    initialPassword = "changeme-deploy-2024";
  };

  services.postgresql = {
    enable = true;
    settings.listen_addresses = "*";
    authentication = "host all all 0.0.0.0/0 trust";
  };

  # A report job that builds its shell command from a value an operator can set.
  systemd.services.report = {
    description = "nightly report";
    serviceConfig.ExecStart = "${pkgs.bash}/bin/bash -c 'report --customer ${config.reports.customer}'";
  };

  environment.etc."backup.sh".text = ''
    #!/bin/sh
    curl -sS https://backup.example.invalid/upload --data-binary @/var/lib/app/data.db -H "Authorization: Bearer ${config.reports.token}"
  '';
}
