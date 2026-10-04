{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad.IO.Class (liftIO)
import Data.String (fromString)
import Database.SQLite.Simple
import System.Process (callCommand)
import System.Random (randomRIO)
import Web.Scotty

-- | Look an order up by reference. The reference comes straight from the URL.
lookupOrder :: Connection -> String -> IO [Only String]
lookupOrder conn ref = query_ conn (fromString ("SELECT status FROM orders WHERE ref = '" ++ ref ++ "'"))

-- | Create a shipping label with an external tool, named after the order.
makeLabel :: String -> IO ()
makeLabel name = callCommand ("label-printer --order " ++ name ++ " --out /srv/labels")

-- | A one-time token for the order status page.
statusToken :: IO Int
statusToken = randomRIO (100000, 999999)

logLogin :: String -> String -> IO ()
logLogin user password = putStrLn ("login " ++ user ++ " password=" ++ password)

main :: IO ()
main = do
  conn <- open "orders.db"
  scotty 3000 $ do
    get "/orders/:ref" $ do
      ref <- param "ref"
      rows <- liftIO (lookupOrder conn ref)
      json (map fromOnly rows)
    post "/orders/label" $ do
      name <- param "name"
      liftIO (makeLabel name)
      text "queued"
    post "/orders/cancel" $ do
      ident <- param "id"
      liftIO (execute conn "DELETE FROM orders WHERE id = ?" (Only (ident :: String)))
      text "cancelled"
