{ config, lib, pkgs, ... }:
let
  appName = "wiki1";
  appPort = 8183;
in
{
  systemd.services.${appName}.description = "wiki service 1";
  networking.hostName = appName;
  environment.etc."wiki.src".source = pkgs.fetchurl { url = "https://example.org/wiki-1.tar.gz"; hash = "sha256-hKAHbfQxo5p4k8zwHBF+SiZc2iWdznbKOHDT5YNn4yU="; };
}
