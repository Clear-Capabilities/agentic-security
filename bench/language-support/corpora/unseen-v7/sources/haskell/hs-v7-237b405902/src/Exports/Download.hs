{-# LANGUAGE OverloadedStrings #-}
module Exports.Download (downloadHandler) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.List (isPrefixOf)
import Snap.Core
import System.Directory (canonicalizePath, doesFileExist)
import System.FilePath ((</>), addTrailingPathSeparator)

exportRoot :: FilePath
exportRoot = "/srv/exports"

downloadHandler :: Snap ()
downloadHandler = do
  mname <- getParam "name"
  case mname of
    Nothing -> badRequest
    Just raw -> do
      resolved <- liftIO (resolveExport (BC.unpack raw))
      case resolved of
        Nothing -> badRequest
        Just path -> do
          modifyResponse (setContentType "application/octet-stream")
          liftIO (BS.readFile path) >>= writeBS
  where
    badRequest = modifyResponse (setResponseStatus 400 "Bad Request") >> writeBS "no such export"

resolveExport :: String -> IO (Maybe FilePath)
resolveExport name = do
  root <- addTrailingPathSeparator <$> canonicalizePath exportRoot
  full <- canonicalizePath (exportRoot </> name)
  exists <- doesFileExist full
  pure (if root `isPrefixOf` full && exists then Just full else Nothing)
