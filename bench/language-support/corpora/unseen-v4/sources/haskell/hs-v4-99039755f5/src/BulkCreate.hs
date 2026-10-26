{-# LANGUAGE OverloadedStrings #-}
module BulkCreate (bulkCreate) where

import Web.Scotty
import Network.HTTP.Types.Status (status400)
import Control.Monad (replicateM_)
import Control.Monad.IO.Class (liftIO)
import Data.IORef

maxBatch :: Int
maxBatch = 100

bulkCreate :: IORef Int -> ActionM ()
bulkCreate counter = do
  n <- param "count" :: ActionM Int
  if n < 0 || n > maxBatch
    then status status400 >> text "count out of range"
    else do
      replicateM_ n (liftIO (modifyIORef' counter (+1)))
      text "ok"
