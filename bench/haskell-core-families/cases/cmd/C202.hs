module C202 where
import System.Process

run :: IO ()
run = do
  h <- getLine
  _ <- readCreateProcess (shell ("ping -c1 " ++ h)) ""
  pure ()
