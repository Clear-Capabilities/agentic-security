{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "office-gw";

  services.unbound.enable = true;

  systemd.services.blocklist-refresh = {
    description = "Refresh the DNS blocklist";
    startAt = "daily";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    preStart = "${pkgs.coreutils}/bin/mkdir -p /var/lib/blocklist";
    script = ''
      ${pkgs.curl}/bin/curl -fsSL -o /var/lib/blocklist/hosts.txt https://lists.example.org/hosts.txt
      ${pkgs.systemd}/bin/systemctl reload unbound.service
    '';
    serviceConfig.Type = "oneshot";
  };
}
