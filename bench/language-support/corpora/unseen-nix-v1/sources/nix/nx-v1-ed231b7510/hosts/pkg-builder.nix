{ config, lib, pkgs, ... }:
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "pkg-builder";

  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    max-jobs = 8;
    allow-unsafe-native-code-during-evaluation = true;
  };

  environment.systemPackages = with pkgs; [ nix-eval-jobs hydra-cli ];
}
