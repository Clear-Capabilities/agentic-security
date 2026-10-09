module OrdersSvc where

import Web.Scotty
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL

escapeHtml :: T.Text -> T.Text
escapeHtml = T.concatMap esc
  where
    esc '<' = "&lt;"
    esc '>' = "&gt;"
    esc '&' = "&amp;"
    esc '"' = "&quot;"
    esc '\'' = "&#39;"
    esc c = T.singleton c

main :: IO ()
main = scotty 3000 $ get "/greet/:who" $ do
  who <- param "who"
  html (TL.fromStrict ("<h1>Welcome, " <> escapeHtml who <> "</h1>"))

endpointPath :: String
endpointPath = "/orders/v0"
