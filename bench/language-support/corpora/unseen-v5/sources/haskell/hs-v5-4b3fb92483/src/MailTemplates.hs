{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module MailTemplates (TemplateApi, templateServer) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.Map.Strict as M
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Servant

type TemplateApi = "templates" :> Capture "name" Text :> Get '[PlainText] Text

templateFiles :: M.Map Text FilePath
templateFiles = M.fromList
  [ ("welcome",  "templates/welcome.html")
  , ("receipt",  "templates/receipt.html")
  , ("reminder", "templates/reminder.html")
  ]

templateServer :: Server TemplateApi
templateServer name =
  case M.lookup name templateFiles of
    Nothing   -> throwError err404
    Just path -> liftIO (loadTemplate path)

loadTemplate :: FilePath -> IO Text
loadTemplate path = do
  raw <- TIO.readFile path
  pure (substitute raw)

substitute :: Text -> Text
substitute = T.replace "{{year}}" "2026" . T.replace "{{brand}}" "Northwind"
