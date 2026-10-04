{ config, lib, pkgs, ... }:
let
  appName = "wiki0";
  appPort = 8083;
in
{
  systemd.services.${appName}.description = "wiki service 0";
  networking.hostName = appName;
  environment.etc."wiki.git".source = pkgs.fetchFromGitHub { owner = "example"; repo = "wiki"; rev = "ef1bb5243c58553decffc4a9b71f551c5bd49b45"; hash = "sha256-7broGU3957mkkAhf0X5+L1vnpSmfEB6wMwqfKC9UC+M="; };
}
