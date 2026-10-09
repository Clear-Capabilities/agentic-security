{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
  unstable = import (builtins.fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") { };
in
{
  networking.hostName = "crm-y0";
  environment.systemPackages = [ unstable.hello ];
}
