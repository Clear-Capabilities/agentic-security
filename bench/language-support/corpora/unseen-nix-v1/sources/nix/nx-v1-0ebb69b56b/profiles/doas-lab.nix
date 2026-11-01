{ config, lib, pkgs, ... }:
with lib;
let
  operators = [ "wheel" ];
in
{
  security.sudo.enable = false;
  security.doas = {
    enable = true;
    extraRules = map (g: { groups = [ g ]; noPass = true; cmd = "/run/current-system/sw/bin/systemctl"; args = [ "restart" "gitea.service" ]; }) operators;
  };

  users.users.sven = { isNormalUser = true; extraGroups = [ "wheel" ]; };
}
