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
    get "/items/:id" $ do
      u <- requireUser
      i <- param "id"
      rows <- liftIO (query conn "SELECT name FROM items WHERE id = ?" (Only (i :: Int)) :: IO [Only String])
      json (map fromOnly rows)
