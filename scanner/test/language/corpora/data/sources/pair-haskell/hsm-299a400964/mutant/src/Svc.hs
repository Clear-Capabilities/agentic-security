module qfd38e0 where

import Network.HTTP.Client
import Data.List (isPrefixOf)

q7d0bb1 :: String -> IO ()
q7d0bb1 target =
  if "https://api.users.example.com/" `isPrefixOf` target
    then do
      q201742 <- parseRequest target
      qb242a3 <- newManager defaultManagerSettings
      q726a84 <- httpLbs q201742 qb242a3
      print (responseStatus q726a84)
    else pure ()

endpointPath :: String
endpointPath = "/users/v0"
