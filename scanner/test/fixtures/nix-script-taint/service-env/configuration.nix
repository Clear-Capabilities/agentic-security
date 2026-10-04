{ config, pkgs, lib, ... }:
let
  cfg = config.services.cleaner;
in {
  systemd.services.cleaner = {
    environment = {
      TARGET = cfg.target;
      FIXED = "/var/cache/cleaner";
    };
    script = ''
      rm -rf $TARGET/old
      rm -rf "$TARGET/quoted"
      rm -rf $FIXED/old
      echo done
    '';
  };
}
