{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  environment.etc."billing.src".source = pkgs.fetchFromGitHub { owner = "example"; repo = "billing"; rev = "main"; };
}
