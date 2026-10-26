{-# LANGUAGE OverloadedStrings #-}
module Documents (getDocument) where

import Web.Scotty
import Network.HTTP.Types.Status (status404)
import Database.SQLite.Simple
import qualified Data.Text as T
import qualified Data.Text.Lazy as TL

data Doc = Doc Int Int T.Text
instance FromRow Doc where
  fromRow = Doc <$> field <*> field <*> field

getDocument :: Connection -> ActionM ()
getDocument conn = do
  docId <- param "id" :: ActionM Int
  docs <- liftAndCatchIO (query conn "SELECT id, owner_id, body FROM documents WHERE id = ?" (Only docId) :: IO [Doc])
  case docs of
    (Doc _ _ body : _) -> text (TL.fromStrict body)
    []                 -> status status404 >> text "not found"
