module C501 where
import System.IO

login :: IO ()
login = do
  password <- getLine
  putStrLn ("login attempt with password " ++ password)
