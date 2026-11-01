{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module ApiKeys (KeyApi, keyServer) where

import Control.Monad (replicateM)
import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import Database.PostgreSQL.Simple
import Servant
import System.Random.MWC (createSystemRandom, uniformR)

type KeyApi = "api-keys" :> Capture "account" Int :> Post '[JSON] Text

alphabet :: String
alphabet = ['a'..'z'] ++ ['A'..'Z'] ++ ['0'..'9']

keyServer :: Connection -> Server KeyApi
keyServer conn account = do
  key <- liftIO newKey
  _ <- liftIO (execute conn "INSERT INTO api_keys (account_id, key_value) VALUES (?, ?)" (account, key))
  pure key

newKey :: IO Text
newKey = do
  gen <- createSystemRandom
  picks <- replicateM 40 (uniformR (0, length alphabet - 1) gen)
  pure (T.pack (map (alphabet !!) picks))
