{-# LANGUAGE OverloadedStrings #-}
module Planetarium.Shows.Manage (manageRoutes, ShowStore(..)) where

import Web.Scotty
import Network.HTTP.Types.Status (status401)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text.Lazy as TL

data ShowStore = ShowStore
  { createShow :: TL.Text -> IO Int
  , cancelShow :: Int -> IO ()
  , listShows :: IO [TL.Text]
  }

requireStaff :: (TL.Text -> IO Bool) -> ActionM () -> ActionM ()
requireStaff isStaffToken action = do
  token <- header "X-Staff-Token"
  allowed <- maybe (pure False) (liftIO . isStaffToken) token
  if allowed then action else status status401 >> text "staff token required"

manageRoutes :: (TL.Text -> IO Bool) -> ShowStore -> ScottyM ()
manageRoutes isStaffToken store = do
  get "/shows" $ do
    names <- liftIO (listShows store)
    json names
  post "/shows" $ requireStaff isStaffToken $ do
    title <- param "title"
    showId <- liftIO (createShow store title)
    json showId
  delete "/shows/:id" $ requireStaff isStaffToken $ do
    showId <- param "id"
    liftIO (cancelShow store showId)
    text "show cancelled"
