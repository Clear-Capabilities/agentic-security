{-# LANGUAGE OverloadedStrings #-}
module Handler.Statement (getStatementR) where

import Data.Text (Text)
import qualified Data.Text as T
import System.FilePath ((</>))
import Yesod.Core

import Foundation

statementDir :: FilePath
statementDir = "/var/lib/billing/statements"

getStatementR :: Text -> Handler TypedContent
getStatementR ref = do
  _ <- requireAuthId
  let path = statementDir </> T.unpack ref
  sendFile "application/pdf" path
