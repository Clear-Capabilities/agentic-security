module C302 where
import System.Directory

drop' :: IO ()
drop' = do
  n <- getLine
  removeFile ("/tmp/up/" ++ n)
