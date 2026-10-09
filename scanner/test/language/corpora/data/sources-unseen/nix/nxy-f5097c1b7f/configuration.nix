{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  networking.wireless.secretsFile = "/run/secrets/wireless.env";
  networking.wireless.networks."billing-office".pskRaw = "ext:billing_office_psk";
}
