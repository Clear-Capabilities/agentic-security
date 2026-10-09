{ config, lib, pkgs, ... }:
let
  cfg = config.services.billing;
in
{
  networking.hostName = "billing-y0";
  nix.settings.extra-substituters = [ "https://cache.billing.example.org" ];
  nix.settings.extra-trusted-public-keys = [ "cache.billing.example.org-1:p56FipE0tqt9gy8iE3M8r4Irx/6+mGQu6gG5jwGPBp8=" ];
}
