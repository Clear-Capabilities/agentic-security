{ config, pkgs, lib, ... }:
{
  imports = [ ./ai.nix ];
  environment.systemPackages = with pkgs; [ ollama git ];
  services.ollama.enable = true;
  services.ollama.loadModels = [ "llama3.1:8b" "nomic-embed-text" ];
}
