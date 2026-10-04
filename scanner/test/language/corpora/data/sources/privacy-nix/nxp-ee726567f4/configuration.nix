{ config, lib, pkgs, ... }:
{
  networking.extraHosts = "10.0.0.1 ${config.services.crm.cardNo}";
}
