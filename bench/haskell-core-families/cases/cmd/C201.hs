module C201 where
import System.Process

run :: IO ()
run = do
  f <- getLine
  callCommand ("tar xf " ++ f)
