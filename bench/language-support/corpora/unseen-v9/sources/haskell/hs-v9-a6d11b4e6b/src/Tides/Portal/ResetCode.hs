{-# LANGUAGE OverloadedStrings #-}
module Tides.Portal.ResetCode (resetRoutes) where

import Web.Scotty
import System.Random (randomRIO)
import Control.Monad (replicateM)
import Control.Monad.IO.Class (liftIO)
import Data.IORef
import qualified Data.Map.Strict as Map
import qualified Data.Text.Lazy as TL

type PendingResets = IORef (Map.Map TL.Text String)

resetRoutes :: PendingResets -> (TL.Text -> String -> IO ()) -> ScottyM ()
resetRoutes pending sendResetMail = post "/portal/reset" $ do
  email <- param "email" :: ActionM TL.Text
  code <- liftIO (replicateM 8 (randomRIO ('0', '9')))
  liftIO (modifyIORef' pending (Map.insert email code))
  liftIO (sendResetMail email code)
  text "a reset code has been sent"
