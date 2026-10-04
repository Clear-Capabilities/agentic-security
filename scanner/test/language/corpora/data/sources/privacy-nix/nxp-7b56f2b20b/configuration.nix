{ config, lib, pkgs, ... }:
{
  environment.etc."crm.log".text = "export ${(if config.services.crm.passport == "" then "none" else "set")}";
}
