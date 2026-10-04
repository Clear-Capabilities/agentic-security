{ config, lib, pkgs, ... }:
{
  networking.extraHosts = "10.0.0.1 ${(if config.services.crm.ipAddress != "" then "set" else "none")}";
}
