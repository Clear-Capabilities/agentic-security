{-# LANGUAGE OverloadedStrings #-}
module OrderLookup (main) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import Database.PostgreSQL.Simple
import Network.HTTP.Types.Status (status404)
import Web.Spock
import Web.Spock.Config

type OrderRow = (Int, Text, Double)

main :: IO ()
main = do
  conn <- connectPostgreSQL "dbname=shop"
  cfg <- defaultSpockCfg () PCNoDatabase ()
  runSpock 8080 $ spock cfg $ do
    get ("orders" <//> var) $ \ref -> do
      rows <- liftIO (query conn "SELECT id, ref, total FROM orders WHERE ref = ? AND cancelled = false" (Only (ref :: Text))) :: ActionCtxT () (WebStateM () () ()) [OrderRow]
      case rows of
        [(i, r, t)] -> json (i, r, t)
        _ -> setStatus status404 >> text "no such order"
    get "orders" $ do
      rows <- liftIO (query_ conn "SELECT id, ref, total FROM orders WHERE cancelled = false LIMIT 50") :: ActionCtxT () (WebStateM () () ()) [OrderRow]
      json rows
