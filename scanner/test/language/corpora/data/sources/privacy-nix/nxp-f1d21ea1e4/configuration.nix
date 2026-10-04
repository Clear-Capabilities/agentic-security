{ config, lib, pkgs, ... }:
{
  environment.etc."crm.log".text = "export ${toString (builtins.stringLength config.services.crm.diagnosis + 0)}";
}
