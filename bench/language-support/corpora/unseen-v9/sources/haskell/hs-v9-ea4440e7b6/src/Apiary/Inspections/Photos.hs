{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module Apiary.Inspections.Photos (PhotoAPI, photoServer) where

import Servant
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString as BS
import qualified Data.Text as T
import System.FilePath ((</>))

type PhotoAPI =
  "inspections" :> Capture "hive" Int :> "photo"
    :> QueryParam' '[Required] "name" T.Text
    :> ReqBody '[OctetStream] BS.ByteString
    :> Put '[JSON] NoContent

photoDir :: FilePath
photoDir = "/srv/apiary/photos"

photoServer :: Server PhotoAPI
photoServer hiveId name bytes = do
  liftIO (BS.writeFile (photoDir </> show hiveId </> T.unpack name) bytes)
  pure NoContent
