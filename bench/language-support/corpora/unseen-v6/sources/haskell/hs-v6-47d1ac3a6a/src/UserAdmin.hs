{-# LANGUAGE OverloadedStrings #-}
module UserAdmin (main) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (object, (.=))
import Database.PostgreSQL.Simple
import Web.Scotty

main :: IO ()
main = do
  conn <- connectPostgreSQL "dbname=accounts"
  scotty 8080 $ do
    get "/admin/users" $ do
      rows <- liftIO (query_ conn "SELECT id, email FROM users ORDER BY id") :: ActionM [(Int, String)]
      json rows
    delete "/admin/users/:id" $ do
      uid <- param "id" :: ActionM Int
      n <- liftIO (execute conn "DELETE FROM users WHERE id = ?" (Only uid))
      json (object ["deleted" .= n])
