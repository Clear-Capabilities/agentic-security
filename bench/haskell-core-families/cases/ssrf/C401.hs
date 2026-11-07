module C401 where
import Network.HTTP.Simple

fetch :: IO ()
fetch = do
  u <- getLine
  req <- parseRequest u
  _ <- httpLBS req
  pure ()
