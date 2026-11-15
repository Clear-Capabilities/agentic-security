{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
module Parcels.Track (trackHandler) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as BL
import Data.Char (isAlphaNum)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Network.HTTP.Req
import Snap.Core

trackHandler :: Snap ()
trackHandler = do
  mcode <- getParam "code"
  case mcode of
    Just raw | BC.length raw <= 32 && BC.all isAlphaNum raw -> do
      body <- liftIO (lookupParcel (TE.decodeUtf8 raw))
      modifyResponse (setContentType "application/json")
      writeLBS body
    _ -> do
      modifyResponse (setResponseStatus 400 "Bad Request")
      writeBS "tracking code must be alphanumeric"

lookupParcel :: T.Text -> IO BL.ByteString
lookupParcel code = runReq defaultHttpConfig $ do
  r <- req GET (https "track.carrier.example" /: "v1" /: "parcels" /~ code) NoReqBody lbsResponse mempty
  pure (responseBody r)
