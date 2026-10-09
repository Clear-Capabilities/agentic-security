{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  networking.wireless.secretsFile = "/run/secrets/wireless.env";
  networking.wireless.networks."crm-office".pskRaw = "ext:crm_office_psk";
}
