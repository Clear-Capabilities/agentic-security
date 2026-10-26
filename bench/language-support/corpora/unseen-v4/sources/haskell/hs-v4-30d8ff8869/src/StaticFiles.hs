{-# LANGUAGE OverloadedStrings #-}
module StaticFiles (serveFile) where

import Web.Scotty
import System.FilePath ((</>), takeFileName)
import qualified Data.Text.Lazy as TL

serveFile :: ActionM ()
serveFile = do
  name <- param "name"
  let path = "public" </> takeFileName (TL.unpack name)
  body <- liftAndCatchIO (readFile path)
  text (TL.pack body)
