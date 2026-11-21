{-# LANGUAGE OverloadedStrings #-}
module Kennel.Sleds.Fleet (fleetRoutes, Session(..)) where

import Web.Spock
import Database.MySQL.Simple
import Network.HTTP.Types.Status (status401)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T

data Session = Session { sessionMusherId :: Int, sessionKennel :: T.Text }

fleetRoutes :: Connection -> SpockM () (Maybe Session) () ()
fleetRoutes conn = get ("sleds" <//> var) $ \sledId -> do
  session <- readSession
  case session of
    Nothing -> setStatus status401 >> text "sign in first"
    Just musher -> do
      rows <- liftIO (query conn "SELECT model, runner_length_cm FROM sleds WHERE id = ? AND musher_id = ?" (sledId :: Int, sessionMusherId musher))
      json (rows :: [(T.Text, Int)])
