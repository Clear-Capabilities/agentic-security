{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  environment.etc."wiki.src".source = pkgs.fetchurl { url = "https://example.org/wiki-0.tar.gz"; hash = "sha256-6pj+0luO+kcWR4ArnYUL0kcyehGzKC3ffxaJOdJKLo8="; };
}
