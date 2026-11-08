module C301 where
import System.IO

serve :: IO String
serve = do
  n <- getLine
  readFile ("/srv/files/" ++ n)
