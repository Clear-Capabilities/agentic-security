{ config, lib, pkgs, ... }:
let
  redisPort = 6379;
in
{
  imports = [ ../modules/base.nix ];
  networking.hostName = "session-store";

  services.redis.servers.sessions = {
    enable = true;
    port = redisPort;
    bind = "127.0.0.1";
    settings.maxmemory = "512mb";
    settings.maxmemory-policy = "allkeys-lru";
  };

  networking.firewall.interfaces.wg0.allowedTCPPorts = [ redisPort ];
}
