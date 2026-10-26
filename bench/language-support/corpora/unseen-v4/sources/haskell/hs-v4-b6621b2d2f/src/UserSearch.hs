{-# LANGUAGE OverloadedStrings #-}
module UserSearch (searchUsers) where

import Database.SQLite.Simple
import Data.String (fromString)
import qualified Data.Text as T
import Web.Scotty

data User = User Int T.Text

instance FromRow User where
  fromRow = User <$> field <*> field

searchUsers :: Connection -> ActionM ()
searchUsers conn = do
  name <- param "name"
  let sql = "SELECT id, name FROM users WHERE name = '" ++ name ++ "'"
  rows <- liftAndCatchIO (query_ conn (fromString sql) :: IO [User])
  json (length rows)
