{ config, lib, pkgs, ... }:
let
  appName = "crm0";
  appPort = 8081;
in
{
  systemd.services.${appName}.description = "crm service 0";
  networking.hostName = appName;
  environment.etc."crm.src".source = pkgs.fetchurl { url = "https://example.org/crm-0.tar.gz"; hash = "sha256-OvnGUF4kRIJFKNYn6VLwwJLAfDwYwsvqB4Ik8v3LPFw="; };
}
