module UsersSvc where

import Network.HTTP.Simple
import qualified Data.ByteString.Char8 as BC

probe :: String -> IO Int
probe hostName = do
  let request = setRequestSecure True (setRequestPort 443 (setRequestHost (BC.pack hostName) defaultRequest))
  resp <- httpLBS request
  pure (getResponseStatusCode resp)

endpointPath :: String
endpointPath = "/users/v0"
