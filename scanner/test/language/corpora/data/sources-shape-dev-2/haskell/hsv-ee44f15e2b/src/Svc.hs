module UsersSvc where

import Web.Scotty
import qualified Data.Text.Lazy as TL

main :: IO ()
main = scotty 3000 $ get "/hello/:who" $ do
  who <- param "who"
  text (TL.pack ("Hello " ++ who))

endpointPath :: String
endpointPath = "/users/v0"
