{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module ApiTokens (TokenApi, tokenServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.UUID as UUID
import Data.UUID.V4 (nextRandom)
import Database.PostgreSQL.Simple
import Servant

type TokenApi = "api-tokens" :> Capture "account" Int :> Post '[JSON] Text

tokenServer :: Connection -> Server TokenApi
tokenServer conn account = do
  token <- liftIO newToken
  _ <- liftIO (execute conn "INSERT INTO api_tokens (account_id, token_value) VALUES (?, ?)" (account, token))
  pure token

newToken :: IO Text
newToken = do
  first  <- nextRandom
  second <- nextRandom
  pure (T.filter (/= '-') (UUID.toText first <> UUID.toText second))
