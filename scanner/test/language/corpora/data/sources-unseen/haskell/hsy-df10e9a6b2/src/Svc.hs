module OrdersSvc where

import Network.HTTP.Client
import Network.HTTP.Client.TLS (tlsManagerSettings)
import qualified Data.ByteString.Char8 as BC

allowedHosts :: [BC.ByteString]
allowedHosts = [BC.pack "hooks.orders.example.com", BC.pack "status.orders.example.com"]

fetch :: String -> IO ()
fetch url = do
  req <- parseRequest url
  if host req `elem` allowedHosts && secure req
    then newManager tlsManagerSettings >>= httpNoBody req >> pure ()
    else ioError (userError "host not allowed")

endpointPath :: String
endpointPath = "/orders/v0"
