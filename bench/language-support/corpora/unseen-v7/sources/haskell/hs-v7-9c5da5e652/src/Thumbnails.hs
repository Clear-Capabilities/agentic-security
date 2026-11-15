{-# LANGUAGE OverloadedStrings #-}
module Thumbnails (thumbnailRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Lazy as TL
import Network.HTTP.Types.Status (status400)
import Network.Wai.Parse (FileInfo(..))
import System.FilePath ((</>), takeFileName)
import System.Process (callCommand)
import Web.Scotty

thumbnailRoutes :: ScottyM ()
thumbnailRoutes =
  post "/badges/photo" $ do
    uploads <- files
    case lookup "photo" uploads of
      Nothing -> status status400 >> text "photo missing"
      Just info -> do
        let name = takeFileName (BC.unpack (fileName info))
            dest = "incoming" </> name
        liftIO (BL.writeFile dest (fileContent info))
        liftIO (makeThumbnail dest)
        text (TL.pack ("stored " ++ name))

makeThumbnail :: FilePath -> IO ()
makeThumbnail src =
  callCommand ("convert " ++ src ++ " -resize 128x128 " ++ src ++ ".thumb.png")
