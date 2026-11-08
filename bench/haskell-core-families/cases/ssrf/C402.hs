module C402 where
import Network.HTTP.Simple

fetch :: IO ()
fetch = do
  h <- getLine
  req <- parseRequest ("http://" ++ h ++ "/status")
  _ <- httpLBS req
  pure ()
