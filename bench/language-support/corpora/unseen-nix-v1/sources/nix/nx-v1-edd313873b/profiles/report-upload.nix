{ config, lib, pkgs, ... }:
with lib;
let
  cfg = config.services.report-upload;
  uploader = pkgs.writeShellApplication {
    name = "report-upload";
    runtimeInputs = [ pkgs.curl ];
    text = ''
      curl -fsS -T /var/lib/reports/latest.json ${cfg.endpoint}
    '';
  };
in
{
  options.services.report-upload = {
    enable = mkEnableOption "nightly report upload";
    endpoint = mkOption {
      type = types.str;
      description = "Where the nightly report is posted.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.report-upload = {
      startAt = "04:00";
      serviceConfig = {
        Type = "oneshot";
        DynamicUser = true;
        ExecStart = "${uploader}/bin/report-upload";
      };
    };
  };
}
