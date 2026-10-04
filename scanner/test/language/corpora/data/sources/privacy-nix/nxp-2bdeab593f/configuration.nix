{ config, lib, pkgs, ... }:
{
  services.nginx.appendHttpConfig = "add_header X-Crm ${toString (builtins.stringLength config.services.crm.ipAddress)};";
}
