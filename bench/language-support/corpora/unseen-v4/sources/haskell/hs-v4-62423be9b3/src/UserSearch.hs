{-# LANGUAGE OverloadedStrings #-}
module UserSearch (searchUsers) where

import Database.SQLite.Simple
import qualified Data.Text as T
import Web.Scotty

data User = User Int T.Text

instance FromRow User where
  fromRow = User <$> field <*> field

searchUsers :: Connection -> ActionM ()
searchUsers conn = do
  name <- param "name" :: ActionM T.Text
  rows <- liftAndCatchIO (query conn "SELECT id, name FROM users WHERE name = ?" (Only name) :: IO [User])
  json (length rows)
