{ config, lib, pkgs, ... }:
let
  appName = "billing1";
  appPort = 8182;
in
{
  systemd.services.${appName}.description = "billing service 1";
  networking.hostName = appName;
  environment.etc."billing.src".source = pkgs.fetchurl { url = "https://example.org/billing-1.tar.gz"; hash = "sha256-mFXRhqXp5M8s3E5RAHkq9narKQ07fxuuJhugDmXm5jM="; };
}
