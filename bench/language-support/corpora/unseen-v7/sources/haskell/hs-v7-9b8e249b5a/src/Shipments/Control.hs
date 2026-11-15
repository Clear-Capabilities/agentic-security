{-# LANGUAGE OverloadedStrings #-}
module Shipments.Control (controlApp) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.HTTP.Types
import Network.Wai

import Shipments.Store (setShipmentState, shipmentState)
import Tokens (tokenValid)

controlApp :: Application
controlApp req respond =
  case (requestMethod req, pathInfo req) of
    ("GET", ["shipments", ref, "state"]) -> do
      st <- shipmentState ref
      respond (responseLBS status200 [("Content-Type", "text/plain")] (BL.fromStrict (TE.encodeUtf8 st)))
    ("PUT", ["shipments", ref, "state"]) -> withBearer req respond (updateState ref)
    _ -> respond (responseLBS status404 [] "")

updateState :: T.Text -> Application
updateState ref req respond = do
  newState <- TE.decodeUtf8 . BL.toStrict <$> strictRequestBody req
  setShipmentState ref (T.strip newState)
  respond (responseLBS status204 [] "")

withBearer :: Request -> (Response -> IO ResponseReceived) -> Application -> IO ResponseReceived
withBearer req respond app =
  case lookup hAuthorization (requestHeaders req) >>= BS.stripPrefix "Bearer " of
    Nothing -> respond (responseLBS status401 [("WWW-Authenticate", "Bearer")] "")
    Just tok -> do
      ok <- tokenValid (TE.decodeUtf8 tok)
      if ok then app req respond else respond (responseLBS status401 [] "")
