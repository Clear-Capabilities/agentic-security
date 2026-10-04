{ lib, config, ... }:
{
  target = config.services.backup.target;
  fromEnv = builtins.getEnv "BACKUP_DIR";
  quote = x: lib.escapeShellArg x;
  fixed = "/var/lib/backup";
}
