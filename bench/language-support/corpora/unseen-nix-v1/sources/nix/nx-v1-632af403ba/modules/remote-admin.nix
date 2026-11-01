{ config, lib, pkgs, ... }:
let
  cfg = config.profiles.remote-admin;
in
{
  options.profiles.remote-admin = {
    enable = lib.mkEnableOption "remote shell access for the support desk";
    port = lib.mkOption { type = lib.types.port; default = 2222; };
  };

  config = lib.mkIf cfg.enable {
    services.openssh = {
      enable = true;
      ports = [ cfg.port ];
      permitRootLogin = "no";
      kbdInteractiveAuthentication = false;
      openFirewall = true;
    };
    services.fail2ban.enable = true;
  };
}
