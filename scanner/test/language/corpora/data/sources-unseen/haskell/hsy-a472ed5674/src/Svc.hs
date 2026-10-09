module UsersSvc where

import Web.Scotty
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL

main :: IO ()
main = scotty 3000 $ get "/greet/:who" $ do
  who <- param "who"
  html (TL.fromStrict ("<h1>Welcome, " <> who <> "</h1>"))

endpointPath :: String
endpointPath = "/users/v0"
