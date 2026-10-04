{ config, pkgs, ... }:
{
  options.customer.email = pkgs.lib.mkOption { type = pkgs.lib.types.str; };

  config.environment.etc."crm-contact.conf".text = ''
    contact_email = ${config.customer.email}
  '';

  config.services.open-webui.enable = true;
  config.services.open-webui.environment.OLLAMA_BASE_URL = "http://127.0.0.1:11434";
}
