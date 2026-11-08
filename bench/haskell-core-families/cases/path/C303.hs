module C303 where
import System.Environment (getArgs)

main :: IO ()
main = do
  (p:_) <- getArgs
  writeFile p "x"
