{-# LANGUAGE OverloadedStrings #-}
module BulkCreate (bulkCreate) where

import Web.Scotty
import Control.Monad (replicateM_, forM_)
import Control.Monad.IO.Class (liftIO)
import Data.IORef

bulkCreate :: IORef Int -> ActionM ()
bulkCreate counter = do
  n <- param "count" :: ActionM Int
  replicateM_ n (liftIO (modifyIORef' counter (+1)))
  text "ok"
