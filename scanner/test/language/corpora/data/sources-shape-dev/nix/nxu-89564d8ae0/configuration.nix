{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  environment.etc."crm.zip".source = pkgs.fetchzip { url = "https://example.org/crm-u0.zip"; hash = "sha256-J9IzhWx52aib3lsEr20ljnIfKWjf/XAdDOfTgWVcz+w="; };
}
