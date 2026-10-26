module ExportApi (exportApi) where

import Servant
import Servant.Auth.Server
import Control.Monad.IO.Class (liftIO)

data Admin = Admin

type ExportAPI = Auth '[JWT] Admin :> "internal" :> "export" :> "customers" :> Get '[PlainText] String

exportApi :: IO [String] -> Server ExportAPI
exportApi loadAll (Authenticated _) = liftIO (unlines <$> loadAll)
exportApi _ _ = throwAll err401
