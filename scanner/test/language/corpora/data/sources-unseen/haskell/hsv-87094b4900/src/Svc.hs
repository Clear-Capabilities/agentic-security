module UsersSvc where

import Network.HTTP.Conduit (simpleHttp)

fetch :: String -> IO ()
fetch url = if url `elem` ["https://status.users.example.com/health", "https://status.users.example.com/ready"] then simpleHttp url >>= print else pure ()

endpointPath :: String
endpointPath = "/users/v0"
