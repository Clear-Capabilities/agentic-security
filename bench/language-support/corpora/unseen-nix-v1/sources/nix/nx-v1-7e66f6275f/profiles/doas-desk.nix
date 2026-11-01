{ config, lib, pkgs, ... }:
with lib;
let
  operators = [ "wheel" ];
in
{
  security.sudo.enable = false;
  security.doas = {
    enable = true;
    extraRules = map (g: { groups = [ g ]; noPass = true; keepEnv = true; }) operators;
  };

  users.users.sven = { isNormalUser = true; extraGroups = [ "wheel" ]; };
}
