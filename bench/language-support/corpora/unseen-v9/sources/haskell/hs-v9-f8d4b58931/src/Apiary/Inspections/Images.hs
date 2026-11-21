{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module Apiary.Inspections.Images (ImageAPI, imageServer) where

import Servant
import Control.Monad.IO.Class (liftIO)
import Data.Char (isAlphaNum)
import qualified Data.ByteString as BS
import qualified Data.Text as T
import System.FilePath ((</>), (<.>))

type ImageAPI =
  "inspections" :> Capture "hive" Int :> "photo"
    :> QueryParam' '[Required] "name" T.Text
    :> ReqBody '[OctetStream] BS.ByteString
    :> Put '[JSON] NoContent

photoDir :: FilePath
photoDir = "/srv/apiary/photos"

plainName :: T.Text -> Bool
plainName name = not (T.null name) && T.all (\c -> isAlphaNum c || c == '-' || c == '_') name

imageServer :: Server ImageAPI
imageServer hiveId name bytes
  | plainName name = do
      liftIO (BS.writeFile (photoDir </> show hiveId </> T.unpack name <.> "jpg") bytes)
      pure NoContent
  | otherwise = throwError err400 { errBody = "photo name may only contain letters, digits, - and _" }
