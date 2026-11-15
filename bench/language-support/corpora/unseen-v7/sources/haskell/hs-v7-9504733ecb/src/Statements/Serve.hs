{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Statements.Serve (StatementApi, statementServer) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Map.Strict as Map
import Data.Text (Text)
import Servant
import System.FilePath ((</>))

type StatementApi =
  "statements" :> Capture "period" Text :> Get '[OctetStream] BL.ByteString

statementDir :: FilePath
statementDir = "/var/lib/billing/statements"

-- known periods and the file each one renders to
periods :: Map.Map Text FilePath
periods = Map.fromList
  [ ("2025-q1", "statement-2025-q1.pdf")
  , ("2025-q2", "statement-2025-q2.pdf")
  , ("2025-q3", "statement-2025-q3.pdf")
  , ("2025-q4", "statement-2025-q4.pdf")
  ]

statementServer :: Server StatementApi
statementServer period =
  case Map.lookup period periods of
    Nothing -> throwError err404 { errBody = "unknown statement period" }
    Just file -> liftIO (BL.readFile (statementDir </> file))
