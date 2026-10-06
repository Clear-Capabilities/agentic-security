{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  services.openssh = { enable = true; settings = { PermitRootLogin = "no"; PasswordAuthentication = false; }; };
}
