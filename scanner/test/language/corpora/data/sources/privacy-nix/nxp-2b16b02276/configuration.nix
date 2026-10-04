{ config, lib, pkgs, ... }:
{
  environment.etc."crm.log".text = "export ${(if config.services.crm.dob != "" then "set" else "none")}";
}
