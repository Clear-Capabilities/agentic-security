{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Accounts.ResetLink (ResetApi, resetServer) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Base16 as B16
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple
import Servant
import System.Entropy (getEntropy)

import Mail (sendResetMail)

type ResetApi =
  "accounts" :> "reset" :> ReqBody '[JSON] Text :> PostNoContent

resetServer :: Connection -> Server ResetApi
resetServer conn email = do
  token <- liftIO (TE.decodeUtf8 . B16.encode <$> getEntropy 24)
  _ <- liftIO (execute conn "INSERT INTO reset_tokens (email, token, issued_at) VALUES (?, ?, now())" (email, token))
  liftIO (sendResetMail email ("https://portal.example/reset/" <> token))
  pure NoContent
