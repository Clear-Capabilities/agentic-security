module C404 where
import Network.HTTP.Simple

fetch :: IO ()
fetch = do
  req <- parseRequest "https://api.example.com/status"
  _ <- httpLBS req
  pure ()
