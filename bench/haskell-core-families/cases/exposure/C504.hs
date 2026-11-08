module C504 where
import System.IO

login :: IO ()
login = do
  _ <- getLine
  putStrLn "login attempt received"
