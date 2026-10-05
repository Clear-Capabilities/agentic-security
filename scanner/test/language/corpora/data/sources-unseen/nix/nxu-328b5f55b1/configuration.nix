{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  environment.etc."billing.git".source = pkgs.fetchgit { url = "https://example.org/billing.git"; rev = "0123456789abcdef0123456789abcdef01234567"; hash = "sha256-6hHhZhvAVk2A9Lp0szwWOyPX4s0W6IaEoNAaj/jCebs="; };
}
