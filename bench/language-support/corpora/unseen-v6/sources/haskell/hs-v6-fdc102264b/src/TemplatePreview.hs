{-# LANGUAGE OverloadedStrings #-}
module TemplatePreview (main) where

import qualified Data.ByteString.Char8 as B
import qualified Data.Map.Strict as Map
import Snap.Core
import Snap.Http.Server (quickHttpServe)

templates :: Map.Map B.ByteString FilePath
templates = Map.fromList
  [ ("welcome", "/srv/templates/welcome.html")
  , ("receipt", "/srv/templates/receipt.html")
  , ("reminder", "/srv/templates/reminder.html")
  ]

main :: IO ()
main = quickHttpServe $ route [("preview/:slug", method GET previewHandler)]

previewHandler :: Snap ()
previewHandler = do
  slug <- getParam "slug"
  maybe missing serveTemplate (slug >>= flip Map.lookup templates)

serveTemplate :: FilePath -> Snap ()
serveTemplate file = do
  modifyResponse (setContentType "text/html; charset=utf-8")
  sendFile file

missing :: Snap ()
missing = do
  modifyResponse (setResponseStatus 404 "Not Found")
  writeBS "no such template"
