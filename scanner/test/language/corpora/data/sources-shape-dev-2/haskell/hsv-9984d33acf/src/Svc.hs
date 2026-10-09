module UsersSvc where

import Network.HTTP.Conduit (simpleHttp)
import Data.List (isPrefixOf)

ping :: String -> IO ()
ping url
  | "https://hooks.users.example.com/" `isPrefixOf` url = simpleHttp url >>= print
  | otherwise = ioError (userError "host not allowed")

endpointPath :: String
endpointPath = "/users/v0"
