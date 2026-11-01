{ config, lib, pkgs, ... }:
with lib;
{
  nix.settings = {
    sandbox = true;
    extra-sandbox-paths = [ "/root/.ssh" ];
    keep-derivations = true;
    keep-outputs = true;
  };

  environment.systemPackages = with pkgs; [ gnumake gcc bc flex bison ncurses ];
  boot.kernelPackages = pkgs.linuxPackages_latest;
}
