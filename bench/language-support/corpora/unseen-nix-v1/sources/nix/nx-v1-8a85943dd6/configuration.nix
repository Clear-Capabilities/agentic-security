{ config, pkgs, ... }:
{
  imports = [ ./hardware-configuration.nix ];

  networking.hostName = "pkg-bench";

  nix.settings = {
    experimental-features = [ "nix-command" "flakes" ];
    max-jobs = 8;
    allow-unsafe-native-code-during-evaluation = false;
  };

  environment.systemPackages = with pkgs; [ nix-eval-jobs hydra-cli ];

  system.stateVersion = "24.05";
}
