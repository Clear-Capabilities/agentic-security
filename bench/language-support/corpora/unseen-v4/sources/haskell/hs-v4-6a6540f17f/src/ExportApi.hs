module ExportApi (exportApi) where

import Servant
import Control.Monad.IO.Class (liftIO)

type ExportAPI = "internal" :> "export" :> "customers" :> Get '[PlainText] String

exportApi :: IO [String] -> Server ExportAPI
exportApi loadAll = liftIO (unlines <$> loadAll)
