module C205 where
import System.Process

run :: IO ()
run = do
  _ <- readProcess "ls" ["-l", "/var/log"] ""
  pure ()
