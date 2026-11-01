{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module EmailTemplates (TemplateApi, templateServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import Servant
import System.FilePath ((</>), (<.>))

type TemplateApi = "templates" :> Capture "name" Text :> Get '[PlainText] Text

templateServer :: Server TemplateApi
templateServer name = liftIO (loadTemplate name)

loadTemplate :: Text -> IO Text
loadTemplate name = do
  raw <- TIO.readFile ("templates" </> T.unpack name <.> "html")
  pure (substitute raw)

substitute :: Text -> Text
substitute = T.replace "{{year}}" "2026" . T.replace "{{brand}}" "Northwind"
