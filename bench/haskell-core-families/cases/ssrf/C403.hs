module C403 where
import Network.HTTP.Simple
import System.Environment (getArgs)

main :: IO ()
main = do
  (u:_) <- getArgs
  req <- parseRequest u
  _ <- httpNoBody req
  pure ()
