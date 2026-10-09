module UsersSvc where

import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import qualified Data.ByteString.Char8 as BC

allowedHosts :: [BC.ByteString]
allowedHosts = [BC.pack "hooks.users.example.com", BC.pack "status.users.example.com"]

fetch :: String -> IO ()
fetch url = do
  req <- parseRequest url
  if host req `elem` allowedHosts && secure req
    then newManager tlsManagerSettings >>= httpNoBody req >> pure ()
    else ioError (userError "host not allowed")

endpointPath :: String
endpointPath = "/users/v0"
