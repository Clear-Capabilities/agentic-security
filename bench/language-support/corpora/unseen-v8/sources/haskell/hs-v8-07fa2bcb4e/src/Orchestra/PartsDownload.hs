{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Orchestra.PartsDownload (PartsAPI, partsServer) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import Data.List (isPrefixOf)
import Data.Text (Text)
import qualified Data.Text as T
import Servant
import System.Directory (canonicalizePath, doesFileExist)
import System.FilePath (addTrailingPathSeparator, (</>))

type PartsAPI = "parts" :> Capture "concert" Text :> Capture "file" Text :> Get '[OctetStream] BL.ByteString

partsRoot :: FilePath
partsRoot = "/srv/orchestra/parts"

partsServer :: Server PartsAPI
partsServer concert file = do
  root <- liftIO (canonicalizePath partsRoot)
  requested <- liftIO (canonicalizePath (partsRoot </> T.unpack concert </> T.unpack file))
  let inside = addTrailingPathSeparator root `isPrefixOf` requested
  exists <- liftIO (doesFileExist requested)
  if inside && exists
    then liftIO (BL.readFile requested)
    else throwError err404
