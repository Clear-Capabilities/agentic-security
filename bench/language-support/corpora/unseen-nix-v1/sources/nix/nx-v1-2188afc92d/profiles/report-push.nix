{ config, lib, pkgs, ... }:
with lib;
let
  cfg = config.services.report-push;
  uploader = pkgs.writeShellApplication {
    name = "report-push";
    runtimeInputs = [ pkgs.curl ];
    text = ''
      curl -fsS -T /var/lib/reports/latest.json ${escapeShellArg cfg.endpoint}
    '';
  };
in
{
  options.services.report-push = {
    enable = mkEnableOption "nightly report upload";
    endpoint = mkOption {
      type = types.str;
      description = "Where the nightly report is posted.";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.report-push = {
      startAt = "04:00";
      serviceConfig = {
        Type = "oneshot";
        DynamicUser = true;
        ExecStart = "${uploader}/bin/report-push";
      };
    };
  };
}
