{-# LANGUAGE OverloadedStrings #-}
module Main where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.PostgreSQL.Simple
import Auth

main :: IO ()
main = do
  conn <- connectPostgreSQL "dbname=app"
  scotty 3000 $ do
    get "/health" $ text "ok"
    get "/public/items" $ do
      rows <- liftIO (query_ conn "SELECT name FROM items" :: IO [Only String])
      json (map fromOnly rows)
    post "/items" $ do
      u <- requireUser
      n <- param "name"
      _ <- liftIO (execute conn "INSERT INTO items (name, owner) VALUES (?, ?)" (n :: String, userId u))
      text "created"
    post "/items/bulk" $ do
      n <- param "name"
      _ <- liftIO (execute conn "INSERT INTO items (name) VALUES (?)" (Only (n :: String)))
      text "bulk"
    get "/items/:id" $ do
      u <- requireUser
      i <- param "id"
      rows <- liftIO (query conn "SELECT name FROM items WHERE id = ? AND owner = ?" (i :: Int, userId u) :: IO [Only String])
      json (map fromOnly rows)
    get "/orders/:id" $ do
      _ <- requireUser
      i <- param "id"
      rows <- liftIO (query conn "SELECT total FROM orders WHERE id = ?" (Only (i :: Int)) :: IO [Only Int])
      json (map fromOnly rows)
    post "/admin/users" $ do
      _ <- requireUser
      n <- param "name"
      _ <- liftIO (execute conn "INSERT INTO users (name) VALUES (?)" (Only (n :: String)))
      text "added"
    post "/admin/purge" $ do
      _ <- requireAdmin
      _ <- liftIO (execute_ conn "DELETE FROM items")
      text "purged"
    post "/late" $ do
      n <- param "name"
      _ <- liftIO (execute conn "INSERT INTO items (name) VALUES (?)" (Only (n :: String)))
      _ <- requireUser
      text "late"
    post "/cookie/settings" $ do
      u <- requireCookieUser
      n <- param "theme"
      _ <- liftIO (execute conn "UPDATE settings SET theme = ? WHERE owner = ?" (n :: String, userId u))
      text "saved"
