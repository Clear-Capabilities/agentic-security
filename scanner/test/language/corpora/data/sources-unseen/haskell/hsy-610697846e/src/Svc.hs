module OrdersSvc where

import Network.HTTP.Req
import Text.URI (mkURI)
import qualified Data.Text as T

fetchRemote :: T.Text -> IO ()
fetchRemote raw = do
  uri <- mkURI raw
  case useURI uri of
    Just (Left (u, o)) -> runReq defaultHttpConfig (req GET u NoReqBody ignoreResponse o) >> pure ()
    Just (Right (u, o)) -> runReq defaultHttpConfig (req GET u NoReqBody ignoreResponse o) >> pure ()
    Nothing -> pure ()

endpointPath :: String
endpointPath = "/orders/v0"
