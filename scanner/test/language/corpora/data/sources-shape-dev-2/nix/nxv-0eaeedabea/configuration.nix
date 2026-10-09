{ config, lib, pkgs, ... }:
let
  cfg = config.services.crm;
in
{
  networking.hostName = "crm-v0";
  environment.etc."crm.src".source = pkgs.fetchFromGitHub { owner = "example"; repo = "crm"; rev = "0123456789abcdef0123456789abcdef01234567"; hash = "sha256-XbSlXQ4GSToyFyh+/0PfxqJesAEb/wxW5t3YuLZgMk0="; };
}
