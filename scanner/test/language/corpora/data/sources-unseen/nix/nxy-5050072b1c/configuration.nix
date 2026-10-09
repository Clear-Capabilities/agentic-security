{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
  unstable = import (builtins.fetchTarball "https://github.com/NixOS/nixpkgs/archive/nixos-unstable.tar.gz") { };
in
{
  networking.hostName = "billing-y0";
  environment.systemPackages = [ unstable.hello ];
}
