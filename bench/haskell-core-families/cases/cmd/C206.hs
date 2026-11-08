module C206 where
import System.Process

run :: IO ()
run = callCommand "date"
