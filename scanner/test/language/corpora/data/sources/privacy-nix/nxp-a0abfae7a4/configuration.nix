{ config, lib, pkgs, ... }:
{
  services.nginx.appendHttpConfig = "add_header X-Crm ${builtins.hashString "sha256" config.services.crm.address};";
}
