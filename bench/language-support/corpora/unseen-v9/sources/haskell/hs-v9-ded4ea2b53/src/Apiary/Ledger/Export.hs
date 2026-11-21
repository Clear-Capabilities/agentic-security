{-# LANGUAGE OverloadedStrings #-}
module Apiary.Ledger.Export (ledgerApp) where

import Network.Wai
import Network.HTTP.Types (status200, status400)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as BC
import System.FilePath ((</>))

ledgerRoot :: FilePath
ledgerRoot = "/var/lib/apiary/ledgers"

ledgerApp :: Application
ledgerApp req respond =
  case lookup "hive" (queryString req) of
    Just (Just hive) -> do
      body <- BL.readFile (ledgerRoot </> BC.unpack hive)
      respond (responseLBS status200 [("Content-Type", "text/csv")] body)
    _ -> respond (responseLBS status400 [] "missing hive")
