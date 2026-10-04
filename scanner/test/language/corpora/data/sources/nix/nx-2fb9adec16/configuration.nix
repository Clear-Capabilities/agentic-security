{ config, lib, pkgs, ... }:
let
  appName = "tracker0";
  appPort = 8085;
in
{
  systemd.services.${appName}.description = "tracker service 0";
  networking.hostName = appName;
  environment.etc."tracker.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "tracker"; rev = "02f00cea9a623e886d2c11d188ae96900059e083"; hash = "sha256-V7OzcCAxAIWLFnD/qnidW5PTRtgs/y9iDIYvweABnWc="; };
}
