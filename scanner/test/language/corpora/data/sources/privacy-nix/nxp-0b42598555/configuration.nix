{ config, lib, pkgs, ... }:
{
  services.nginx.appendHttpConfig = "add_header X-Crm ${(if config.services.crm.cardNo == "" then "none" else "set")};";
}
