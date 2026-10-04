{ config, lib, pkgs, ... }:
{
  services.nginx.appendHttpConfig = "add_header X-Crm ${config.services.crm.ssn + "/ipAddress"};";
}
