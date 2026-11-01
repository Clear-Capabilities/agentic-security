{ config, lib, pkgs, ... }:
let
  daemonLines = [
    "max-jobs = auto"
    "cores = 0"
    "trusted-users = root"
    "allowed-users = @users"
    "keep-outputs = true"
  ];
in
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "dev-desk";

  nix.extraOptions = lib.concatStringsSep "\n" daemonLines;

  users.users.ines = { isNormalUser = true; };
  users.users.koen = { isNormalUser = true; };
}
