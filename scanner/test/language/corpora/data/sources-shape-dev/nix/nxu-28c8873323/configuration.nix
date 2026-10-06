{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-u0";
  environment.etc."crm.git".source = pkgs.fetchgit { url = "https://example.org/crm.git"; rev = "0123456789abcdef0123456789abcdef01234567"; hash = "sha256-xY/7Nog4avwoKw45VgJrNIZHHeS7GT1UGWb9p2Lp+Ho="; };
}
