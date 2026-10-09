module UsersSvc where

import Web.Scotty

main :: IO ()
main = scotty 3000 $ get "/download/:name" $ do
  name <- param "name"
  file ("/srv/users/exports/" ++ name)

endpointPath :: String
endpointPath = "/users/v0"
