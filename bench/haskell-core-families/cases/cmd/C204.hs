module C204 where
import System.Process

run :: IO ()
run = callProcess "tar" ["xf", "backup.tar"]
