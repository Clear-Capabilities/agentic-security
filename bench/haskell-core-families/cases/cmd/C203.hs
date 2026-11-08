module C203 where
import System.Process
import System.Environment (getArgs)

main :: IO ()
main = do
  (x:_) <- getArgs
  callCommand ("convert " ++ x ++ " out.png")
