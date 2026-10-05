module UsersSvc where

import Network.HTTP.Conduit (simpleHttp)
import Data.List (isPrefixOf)

grab :: String -> IO ()
grab url
  | "https://assets.users.example.com/" `isPrefixOf` url = simpleHttp url >>= print
  | otherwise = pure ()

endpointPath :: String
endpointPath = "/users/u0"
