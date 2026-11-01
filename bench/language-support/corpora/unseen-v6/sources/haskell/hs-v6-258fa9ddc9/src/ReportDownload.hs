{-# LANGUAGE OverloadedStrings #-}
module ReportDownload (getReportDownloadR) where

import Data.Text (Text)
import qualified Data.Text as T
import System.FilePath ((</>))
import Yesod.Core
import Foundation (Handler)

reportRoot :: FilePath
reportRoot = "/var/lib/reports"

reportPath :: Text -> FilePath
reportPath name = reportRoot </> T.unpack name

getReportDownloadR :: Handler TypedContent
getReportDownloadR = do
  requested <- lookupGetParam "file"
  case requested of
    Nothing -> invalidArgs ["file"]
    Just name -> do
      addHeader "Cache-Control" "private, no-store"
      sendFile "application/pdf" (reportPath name)
