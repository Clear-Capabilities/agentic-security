{ config, lib, pkgs, ... }:
let
  appName = "tracker1";
  appPort = 8185;
in
{
  systemd.services.${appName}.description = "tracker service 1";
  networking.hostName = appName;
  environment.etc."tracker.src".source = pkgs.fetchurl { url = "https://example.org/tracker-1.tar.gz"; hash = "sha256-8QBZnhr/H6iREjh9h1maOLMN1tRrlSbJE2n/slTD8LU="; };
}
