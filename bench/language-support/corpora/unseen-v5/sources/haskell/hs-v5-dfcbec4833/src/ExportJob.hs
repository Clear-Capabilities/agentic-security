{-# LANGUAGE OverloadedStrings, QuasiQuotes, TemplateHaskell, TypeFamilies #-}
module ExportJob (postExportR) where

import Data.Text (Text)
import qualified Data.Text as T
import System.Process (spawnCommand, waitForProcess)
import Yesod
import Foundation

data ExportRequest = ExportRequest
  { exportFolder :: Text
  , exportFormat :: Text
  }

exportForm :: FormInput Handler ExportRequest
exportForm = ExportRequest <$> ireq textField "folder" <*> ireq textField "format"

postExportR :: Handler Value
postExportR = do
  request <- runInputPost exportForm
  ph <- liftIO (spawnCommand (bundleCommand request))
  _ <- liftIO (waitForProcess ph)
  returnJson (object ["folder" .= exportFolder request, "format" .= exportFormat request])

bundleCommand :: ExportRequest -> String
bundleCommand r = "tar czf exports/" <> folder <> ".tgz exports/" <> folder
  where
    folder = T.unpack (exportFolder r)
