{-# LANGUAGE OverloadedStrings #-}
module Attachments (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Lazy as TL
import System.FilePath (takeFileName, (</>))
import Web.Scotty

attachmentRoot :: FilePath
attachmentRoot = "/srv/uploads/attachments"

main :: IO ()
main = scotty 8080 $ do
  get "/attachments/:name" $ do
    name <- param "name"
    let file = takeFileName (TL.unpack name)
    bytes <- liftIO (BL.readFile (attachmentRoot </> file))
    setHeader "Content-Type" "application/octet-stream"
    setHeader "Cache-Control" "private, max-age=600"
    raw bytes
  get "/attachments" $
    json ["invoice-march.pdf", "contract.pdf" :: TL.Text]
