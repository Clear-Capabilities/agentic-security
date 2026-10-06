{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-v0";
  environment.etc."billing.src".source = pkgs.fetchFromGitHub { owner = "example"; repo = "billing"; rev = "0123456789abcdef0123456789abcdef01234567"; hash = "sha256-phSuL69i9ncwoibmsN8HKhG2EpSzITm4W7oDRIteXEo="; };
}
