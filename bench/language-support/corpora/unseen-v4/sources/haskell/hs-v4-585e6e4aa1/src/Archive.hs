module Archive (backup) where

import System.Process
import System.Exit

-- The directory to archive is fixed by the program, not by the caller.
backup :: IO ExitCode
backup = do
  (_, _, _, ph) <- createProcess (proc "tar" ["czf", "/tmp/backup.tgz", "/var/lib/app/data"])
  waitForProcess ph
