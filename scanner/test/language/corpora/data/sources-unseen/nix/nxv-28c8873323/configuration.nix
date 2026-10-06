{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  environment.etc."crm.json".source = builtins.fetchurl { url = "https://example.org/crm-v0.json"; sha256 = "sha256-QyvavJ4AqXHnRHdt2C08GCIaQWjXTTMQC2Fszgz+z7Y="; };
}
