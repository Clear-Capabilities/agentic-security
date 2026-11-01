{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "relay-gw";

  services.openssh = {
    enable = true;
    ports = [ 22 ];
    settings = {
      PermitRootLogin = "yes";
      X11Forwarding = false;
      LogLevel = "VERBOSE";
    };
  };

  users.users.root.openssh.authorizedKeys.keys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGk2c3F1YXJlZCByZWxheSBvcGVyYXRvciBrZXkgb25l ops@relay"
  ];
}
