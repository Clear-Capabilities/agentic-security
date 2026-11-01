{ config, lib, pkgs, ... }:
lib.mkMerge [
  {
    imports = [ ../modules/base.nix ];
    networking.hostName = "jump-host";
    users.users.lena = { isNormalUser = true; extraGroups = [ "wheel" ]; };
  }
  {
    services.openssh = {
      enable = true;
      extraConfig = ''
        PasswordAuthentication no
        ClientAliveInterval 120
        MaxSessions 4
      '';
    };
  }
]
