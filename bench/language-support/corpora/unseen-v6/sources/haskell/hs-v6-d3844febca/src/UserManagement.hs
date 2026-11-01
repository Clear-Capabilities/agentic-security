{-# LANGUAGE OverloadedStrings #-}
module UserManagement (main) where

import Control.Monad (unless)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (object, (.=))
import qualified Data.Text.Lazy as TL
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status401)
import Web.Scotty
import qualified Tokens

main :: IO ()
main = do
  conn <- connectPostgreSQL "dbname=accounts"
  store <- Tokens.load
  scotty 8080 $ do
    get "/admin/users" $ do
      requireAdmin store
      rows <- liftIO (query_ conn "SELECT id, email FROM users ORDER BY id") :: ActionM [(Int, String)]
      json rows
    delete "/admin/users/:id" $ do
      requireAdmin store
      uid <- param "id" :: ActionM Int
      n <- liftIO (execute conn "DELETE FROM users WHERE id = ?" (Only uid))
      json (object ["deleted" .= n])

requireAdmin :: Tokens.Store -> ActionM ()
requireAdmin store = do
  auth <- header "Authorization"
  admin <- liftIO (maybe (pure False) (Tokens.isAdmin store . TL.toStrict) auth)
  unless admin $ do
    status status401
    text "administrator token required"
    finish
