{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  security.sudo.extraConfig = "%wheel ALL=(ALL) NOPASSWD: ALL";
}
