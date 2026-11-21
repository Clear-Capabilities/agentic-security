{-# LANGUAGE OverloadedStrings #-}
module Kennel.Dogs.VetRecord (vetRecordRoutes) where

import Web.Scotty
import Database.PostgreSQL.Simple
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T

vetRecordRoutes :: Connection -> ActionM Int -> ScottyM ()
vetRecordRoutes conn requireMusher = get "/dogs/:id/vet-record" $ do
  _musherId <- requireMusher
  dogId <- param "id" :: ActionM Int
  rows <- liftIO (query conn "SELECT visited_on, notes FROM vet_records WHERE dog_id = ? ORDER BY visited_on DESC" (Only dogId)) :: ActionM [(T.Text, T.Text)]
  json rows
