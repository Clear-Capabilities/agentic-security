{ config, lib, pkgs, ... }:
lib.mkMerge [
  { networking.firewall.enable = true; }
  { networking.firewall.interfaces."lo".allowedTCPPortRanges = [ { from = 1024; to = 65535; } ]; }
]
