{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "build-farm-b";

  nix.settings = {
    max-jobs = 16;
    cores = 4;
    sandbox = true;
    experimental-features = [ "nix-command" "flakes" ];
  };

  nix.gc.automatic = true;
  services.hydra.enable = false;
}
