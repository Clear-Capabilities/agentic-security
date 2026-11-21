{-# LANGUAGE OverloadedStrings #-}
module Apiary.Ledger.Download (ledgerApp) where

import Network.Wai
import Network.HTTP.Types (status200, status400, status403)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as BC
import Data.List (isPrefixOf)
import System.Directory (canonicalizePath)
import System.FilePath ((</>))

ledgerRoot :: FilePath
ledgerRoot = "/var/lib/apiary/ledgers"

ledgerApp :: Application
ledgerApp req respond =
  case lookup "hive" (queryString req) of
    Just (Just hive) -> do
      resolved <- canonicalizePath (ledgerRoot </> BC.unpack hive)
      rootResolved <- canonicalizePath ledgerRoot
      if (rootResolved ++ "/") `isPrefixOf` resolved
        then do
          body <- BL.readFile resolved
          respond (responseLBS status200 [("Content-Type", "text/csv")] body)
        else respond (responseLBS status403 [] "ledger not available")
    _ -> respond (responseLBS status400 [] "missing hive")
