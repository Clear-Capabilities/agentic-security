{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  services.postfix.enable = true;
  services.postfix.sslKey = ./billing-mail.key;
}
