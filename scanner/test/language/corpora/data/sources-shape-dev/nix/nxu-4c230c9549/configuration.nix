{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  nix.extraOptions = "trusted-users = root *";
}
