{ config, lib, pkgs, ... }:
{
  services.nginx.appendHttpConfig = "add_header X-Crm ${(if config.services.crm.passport != "" then "set" else "none")};";
}
