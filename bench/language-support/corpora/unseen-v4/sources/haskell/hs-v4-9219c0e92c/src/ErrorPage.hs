module ErrorPage (notFoundPage) where

import Network.Wai
import Network.HTTP.Types
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as BL

escape :: String -> String
escape = concatMap f
  where
    f '<' = "&lt;"
    f '>' = "&gt;"
    f '&' = "&amp;"
    f '"' = "&quot;"
    f '\'' = "&#39;"
    f c = [c]

notFoundPage :: Request -> Response
notFoundPage req =
  responseLBS status404 [(hContentType, B.pack "text/html")] page
  where
    path = escape (B.unpack (rawPathInfo req))
    page = BL.pack ("<html><body><p>No such page: " ++ path ++ "</p></body></html>")
