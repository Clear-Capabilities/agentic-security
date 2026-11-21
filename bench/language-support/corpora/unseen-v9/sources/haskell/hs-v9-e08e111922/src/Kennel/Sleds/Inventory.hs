{-# LANGUAGE OverloadedStrings #-}
module Kennel.Sleds.Inventory (sledRoutes, Session(..)) where

import Web.Spock
import Database.MySQL.Simple
import Network.HTTP.Types.Status (status401)
import Control.Monad.IO.Class (liftIO)
import qualified Data.Text as T

data Session = Session { sessionMusherId :: Int, sessionKennel :: T.Text }

sledRoutes :: Connection -> SpockM () (Maybe Session) () ()
sledRoutes conn = get ("sleds" <//> var) $ \sledId -> do
  session <- readSession
  case session of
    Nothing -> setStatus status401 >> text "sign in first"
    Just _musher -> do
      rows <- liftIO (query conn "SELECT model, runner_length_cm FROM sleds WHERE id = ?" (Only (sledId :: Int)))
      json (rows :: [(T.Text, Int)])
