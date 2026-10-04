{ config, lib, pkgs, ... }:
{
  environment.etc."crm.log".text = "export ${(if config.services.crm.salary != "" then "set" else "none")}";
}
