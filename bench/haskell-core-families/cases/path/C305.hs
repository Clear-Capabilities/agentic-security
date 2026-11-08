module C305 where
import System.Directory
import System.FilePath (takeFileName)

drop' :: IO ()
drop' = do
  n <- getLine
  removeFile ("/tmp/up/" ++ takeFileName n)
