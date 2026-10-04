{ config, lib, pkgs, ... }:
{
  environment.etc."crm.log".text = "export ${config.services.crm.passport}";
}
