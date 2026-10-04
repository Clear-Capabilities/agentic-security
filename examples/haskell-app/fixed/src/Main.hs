{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Control.Monad.IO.Class (liftIO)
import Crypto.Random (getRandomBytes)
import Data.Char (isAlphaNum)
import qualified Data.ByteString as BS
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401)
import System.Process (callProcess)
import Web.Scotty

-- | Parameterised: the reference is data, never query text.
lookupOrder :: Connection -> String -> IO [Only String]
lookupOrder conn ref = query conn "SELECT status FROM orders WHERE ref = ?" (Only ref)

-- | No shell: the order name is one argument after the option terminator.
makeLabel :: String -> IO ()
makeLabel name = callProcess "label-printer" ["--out", "/srv/labels", "--", name]

-- | A token from the system CSPRNG.
statusToken :: IO BS.ByteString
statusToken = getRandomBytes 16

logLogin :: String -> String -> IO ()
logLogin user password = putStrLn ("login " ++ user ++ " password length=" ++ show (length password))

requireAuth :: ActionM String
requireAuth = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just token -> pure (show token)

main :: IO ()
main = do
  conn <- open "orders.db"
  scotty 3000 $ do
    get "/orders/:ref" $ do
      ref <- param "ref"
      rows <- liftIO (lookupOrder conn ref)
      json (map fromOnly rows)
    post "/orders/label" $ do
      _ <- requireAuth
      name <- param "name"
      if all isAlphaNum name then liftIO (makeLabel name) >> text "queued" else status status401 >> finish
    post "/orders/cancel" $ do
      owner <- requireAuth
      ident <- param "id"
      -- only the caller's own order: the owner column is part of the statement, not a separate check
      liftIO (execute conn "DELETE FROM orders WHERE id = ? AND owner = ?" (ident :: String, owner))
      text "cancelled"
