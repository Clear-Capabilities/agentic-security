{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  environment.etc."crm.src".source = pkgs.fetchFromGitHub { owner = "example"; repo = "crm"; rev = "main"; };
}
