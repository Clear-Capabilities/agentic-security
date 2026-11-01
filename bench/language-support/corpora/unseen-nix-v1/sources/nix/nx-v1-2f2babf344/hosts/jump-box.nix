{ config, lib, pkgs, ... }:
lib.mkMerge [
  {
    imports = [ ../modules/base.nix ];
    networking.hostName = "jump-box";
    users.users.lena = { isNormalUser = true; extraGroups = [ "wheel" ]; };
  }
  {
    services.openssh = {
      enable = true;
      extraConfig = ''
        PasswordAuthentication yes
        ClientAliveInterval 120
        MaxSessions 4
      '';
    };
  }
]
