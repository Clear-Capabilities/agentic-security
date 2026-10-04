{ config, lib, pkgs, ... }:
{
  environment.etc."crm.log".text = "export ${builtins.hashString "sha256" config.services.crm.ipAddress}";
}
