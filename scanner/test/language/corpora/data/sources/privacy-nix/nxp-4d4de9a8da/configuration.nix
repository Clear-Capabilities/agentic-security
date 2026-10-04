{ config, lib, pkgs, ... }:
{
  networking.extraHosts = "10.0.0.1 ${(if config.services.crm.address == "" then "none" else "set")}";
}
