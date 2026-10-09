{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  services.postfix.enable = true;
  services.postfix.sslKey = ./crm-mail.key;
}
