{ config, lib, pkgs, ... }:
{
  environment.etc."crm.log".text = "export ${(if config.services.crm.ssn == "" then "none" else "set")}";
}
