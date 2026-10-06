{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  security.sudo.extraConfig = "%wheel ALL=(ALL) NOPASSWD: ALL";
}
