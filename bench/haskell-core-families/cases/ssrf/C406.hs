module C406 where
import Network.HTTP.Simple

fetch :: IO ()
fetch = do
  req <- parseRequest "https://internal.example.com/health"
  _ <- httpNoBody req
  pure ()
