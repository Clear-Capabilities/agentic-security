{-# LANGUAGE OverloadedStrings #-}
module Tickets.Annotate (annotateRoutes) where

import Control.Monad.IO.Class (liftIO)
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status401, status404)
import Web.Spock

import Portal.Session (SessionData(..))

annotateRoutes :: Connection -> SpockM () SessionData () ()
annotateRoutes conn =
  put ("tickets" <//> var <//> "notes") $ \tid -> do
    sess <- readSession
    case sessionUser sess of
      Nothing -> setStatus status401 >> text "sign in first"
      Just uid -> do
        notes <- body
        changed <- liftIO (execute conn "UPDATE tickets SET notes = ? WHERE id = ? AND reporter_id = ?" (notes, tid :: Int, uid))
        if changed == 0
          then setStatus status404 >> text "no such ticket"
          else text "notes saved"
