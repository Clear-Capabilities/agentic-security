{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Accounts.Reset (ResetApi, resetServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import Database.PostgreSQL.Simple
import Servant
import System.Random (randomRIO)

import Mail (sendResetMail)

type ResetApi =
  "accounts" :> "reset" :> ReqBody '[JSON] Text :> PostNoContent

resetServer :: Connection -> Server ResetApi
resetServer conn email = do
  code <- liftIO (randomRIO (100000, 999999 :: Int))
  let codeText = T.pack (show code)
  _ <- liftIO (execute conn "INSERT INTO reset_codes (email, code, issued_at) VALUES (?, ?, now())" (email, codeText))
  liftIO (sendResetMail email codeText)
  pure NoContent
