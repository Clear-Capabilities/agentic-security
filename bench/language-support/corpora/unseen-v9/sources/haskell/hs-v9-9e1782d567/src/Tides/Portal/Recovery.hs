{-# LANGUAGE OverloadedStrings #-}
module Tides.Portal.Recovery (recoveryRoutes) where

import Web.Scotty
import Crypto.Random (getRandomBytes)
import Control.Monad.IO.Class (liftIO)
import Data.IORef
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import qualified Data.Map.Strict as Map
import qualified Data.Text.Lazy as TL

type PendingResets = IORef (Map.Map TL.Text String)

recoveryRoutes :: PendingResets -> (TL.Text -> String -> IO ()) -> ScottyM ()
recoveryRoutes pending sendResetMail = post "/portal/reset" $ do
  email <- param "email" :: ActionM TL.Text
  raw <- liftIO (getRandomBytes 6 :: IO BS.ByteString)
  let code = BC.unpack (B16.encode raw)
  liftIO (modifyIORef' pending (Map.insert email code))
  liftIO (sendResetMail email code)
  text "a reset code has been sent"
