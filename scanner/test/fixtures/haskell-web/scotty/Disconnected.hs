{-# LANGUAGE OverloadedStrings #-}
-- Authentication is DECLARED here (a type signature, a guard function, an unused import) but never applied
-- to the handler: none of it may count as enforcement.
module Main where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.PostgreSQL.Simple
import Auth (requireUser, User(..))

-- looks like a protected handler by its type, never calls a guard
deleteAccount :: ActionM ()
deleteAccount = do
  n <- param "name"
  conn <- liftIO (connectPostgreSQL "dbname=app")
  _ <- liftIO (execute conn "DELETE FROM accounts WHERE name = ?" (Only (n :: String)))
  text "gone"

-- a guard-shaped function that never rejects anything
checkUser :: ActionM ()
checkUser = do
  _ <- header "Authorization"
  pure ()

main :: IO ()
main = scotty 3000 $ do
  post "/account/delete" deleteAccount
  post "/account/rename" $ do
    checkUser
    n <- param "name"
    conn <- liftIO (connectPostgreSQL "dbname=app")
    _ <- liftIO (execute conn "UPDATE accounts SET name = ?" (Only (n :: String)))
    text "renamed"
