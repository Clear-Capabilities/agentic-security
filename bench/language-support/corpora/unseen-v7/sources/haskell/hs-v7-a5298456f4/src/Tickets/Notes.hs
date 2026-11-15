{-# LANGUAGE OverloadedStrings #-}
module Tickets.Notes (noteRoutes) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status401)
import Web.Spock

import Portal.Session (SessionData(..))

noteRoutes :: Connection -> SpockM () SessionData () ()
noteRoutes conn =
  put ("tickets" <//> var <//> "notes") $ \tid -> do
    sess <- readSession
    case sessionUser sess of
      Nothing -> setStatus status401 >> text "sign in first"
      Just _uid -> do
        notes <- body
        _ <- liftIO (execute conn "UPDATE tickets SET notes = ? WHERE id = ?" (notes, tid :: Int))
        text "notes saved"
