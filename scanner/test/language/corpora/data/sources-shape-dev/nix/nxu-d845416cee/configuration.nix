{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-u0";
  environment.etc."billing.tar".source = builtins.fetchTarball { url = "https://example.org/billing-u0.tar.gz"; sha256 = "sha256-OMQL9VWY8ECupvqabJjR+F8EGr70xntqP5Ee2og7dAQ="; };
}
