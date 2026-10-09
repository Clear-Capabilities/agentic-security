module OrdersSvc where

import Web.Scotty

main :: IO ()
main = scotty 3000 $ get "/download/:name" $ do
  name <- param "name"
  file ("/srv/orders/exports/" ++ name)

endpointPath :: String
endpointPath = "/orders/v0"
