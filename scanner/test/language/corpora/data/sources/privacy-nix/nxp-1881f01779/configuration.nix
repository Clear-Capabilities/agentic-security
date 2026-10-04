{ config, lib, pkgs, ... }:
{
  services.nginx.appendHttpConfig = "add_header X-Crm ${(if config.services.crm.phone == "" then "none" else "set")};";
}
