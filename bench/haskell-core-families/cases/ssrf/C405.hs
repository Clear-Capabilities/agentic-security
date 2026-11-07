module C405 where
import Network.HTTP.Simple

fetch :: IO ()
fetch = do
  n <- getLine
  req <- parseRequest "https://api.example.com/items"
  _ <- httpLBS (setRequestQueryString [("name", Just (fromStr n))] req)
  pure ()
  where fromStr = undefined
