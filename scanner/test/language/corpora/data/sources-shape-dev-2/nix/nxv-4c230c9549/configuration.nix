{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  nix.settings = { trusted-users = [ "*" ]; };
}
