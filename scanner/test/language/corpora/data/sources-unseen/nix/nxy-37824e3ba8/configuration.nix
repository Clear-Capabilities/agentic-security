{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-y0";
  nix.settings.extra-substituters = [ "https://cache.crm.example.org" ];
  nix.settings.extra-trusted-public-keys = [ "cache.crm.example.org-1:6EGSr9RrfJbzWI2NNOIMVJlx3Jfao5ct1AGDtnk2LTQ=" ];
}
