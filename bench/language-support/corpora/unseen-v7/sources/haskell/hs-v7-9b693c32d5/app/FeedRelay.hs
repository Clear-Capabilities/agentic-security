{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad (forever)
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Req
import qualified Network.WebSockets as WS
import Text.URI (mkURI)

main :: IO ()
main = WS.runServer "0.0.0.0" 9160 relay

relay :: WS.ServerApp
relay pending = do
  conn <- WS.acceptRequest pending
  forever $ do
    msg <- WS.receiveData conn :: IO Text
    body <- fetchFeed (T.strip msg)
    WS.sendBinaryData conn body

fetchFeed :: Text -> IO BL.ByteString
fetchFeed target = do
  uri <- mkURI target
  case useHttpsURI uri of
    Nothing -> pure "feed address must be https"
    Just (url, opts) -> runReq defaultHttpConfig $ do
      r <- req GET url NoReqBody lbsResponse opts
      pure (responseBody r)
