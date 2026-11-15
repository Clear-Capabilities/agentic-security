{-# LANGUAGE OverloadedStrings #-}
module Apiary.HiveAdmin (HiveStore (..), hiveRoutes) where

import Control.Monad (unless)
import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text.Lazy as TL
import Network.HTTP.Types.Status (status401)
import Web.Scotty

data HiveStore = HiveStore
  { listHives :: IO [Text]
  , renameHive :: Int -> Text -> IO ()
  , removeHive :: Int -> IO ()
  }

requireKeeper :: Text -> ActionM ()
requireKeeper expected = do
  provided <- header "X-Keeper-Key"
  unless (provided == Just (TL.fromStrict expected)) $ do
    status status401
    text "keeper key required"
    finish

hiveRoutes :: Text -> HiveStore -> ScottyM ()
hiveRoutes keeperKey store = do
  get "/hives" $ liftIO (listHives store) >>= json
  put "/hives/:id" $ do
    requireKeeper keeperKey
    hid <- param "id"
    name <- param "name"
    liftIO (renameHive store hid name)
    text "renamed"
  delete "/hives/:id" $ do
    hid <- param "id"
    liftIO (removeHive store hid)
    text "removed"
