{ config, pkgs, lib, ... }:
let
  old = import <nixpkgs> { };
  floating = builtins.fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz";
  pinned = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/0123456789abcdef0123456789abcdef01234567.tar.gz";
    sha256 = "0000000000000000000000000000000000000000000000000000";
  };
  local = import /home/dev/overlays/mine.nix;
in {
  nix.nixPath = [ "nixpkgs=/nix/var/nix/profiles/per-user/root/channels/nixos" "nixos-config=/etc/nixos/configuration.nix" ];
  nix.channel.enable = true;
  system.autoUpgrade.channel = "https://nixos.org/channels/nixos-24.05";
  environment.systemPackages = [ old.hello ];
}
