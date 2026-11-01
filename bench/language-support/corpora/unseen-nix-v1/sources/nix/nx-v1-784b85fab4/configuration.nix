{ config, pkgs, ... }:
{
  imports = [ ./hardware-configuration.nix ];

  networking.hostName = "field-tablet";
  networking.wireless = {
    enable = true;
    environmentFile = "/run/secrets/wireless.env";
    networks."office-5g".pskRaw = "ext:OFFICE_PSK";
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
