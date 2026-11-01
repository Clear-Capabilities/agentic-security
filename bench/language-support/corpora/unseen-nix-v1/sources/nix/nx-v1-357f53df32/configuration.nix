{ config, pkgs, ... }:
{
  imports = [ ./hardware-configuration.nix ];

  networking.hostName = "field-laptop";
  networking.wireless = {
    enable = true;
    networks."office-5g".psk = "Wint3r-Garden-2024";
    networks."eduroam".auth = ''
      key_mgmt=WPA-EAP
      eap=PEAP
      identity="rhall@example.edu"
    '';
  };

  users.users.rhall = {
    isNormalUser = true;
    extraGroups = [ "networkmanager" "video" ];
  };

  system.stateVersion = "24.05";
}
