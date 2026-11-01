{ config, lib, pkgs, ... }:
let
  redisPort = 6379;
in
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "session-cache";

  services.redis.servers.sessions = {
    enable = true;
    port = redisPort;
    bind = "0.0.0.0";
    settings.maxmemory = "512mb";
    settings.maxmemory-policy = "allkeys-lru";
  };

  networking.firewall.allowedTCPPorts = [ redisPort ];
}
