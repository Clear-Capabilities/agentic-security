{-# LANGUAGE OverloadedStrings #-}
module Kennel.Dogs.Health (healthRoutes) where

import Web.Scotty
import Database.PostgreSQL.Simple
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T

healthRoutes :: Connection -> ActionM Int -> ScottyM ()
healthRoutes conn requireMusher = get "/dogs/:id/vet-record" $ do
  musherId <- requireMusher
  dogId <- param "id" :: ActionM Int
  rows <- liftIO (query conn "SELECT visited_on, notes FROM vet_records WHERE dog_id = ? AND musher_id = ? ORDER BY visited_on DESC" (dogId, musherId)) :: ActionM [(T.Text, T.Text)]
  json rows
