{-# LANGUAGE OverloadedStrings #-}
module Apiary.Photos (photoRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString as BS
import Data.Char (isAlphaNum)
import Data.Text (Text)
import qualified Data.Text as T
import Network.HTTP.Types (status400)
import Web.Spock

photoDir :: FilePath
photoDir = "/srv/apiary/photos/"

hiveNameOk :: Text -> Bool
hiveNameOk n = not (T.null n) && T.length n <= 32 && T.all (\c -> isAlphaNum c || c == '-') n

photoRoutes :: SpockM () () () ()
photoRoutes =
  get ("hives" <//> var <//> "photo") $ \hive ->
    if hiveNameOk hive
      then do
        img <- liftIO (BS.readFile (photoDir ++ T.unpack hive ++ ".jpg"))
        setHeader "Content-Type" "image/jpeg"
        bytes img
      else do
        setStatus status400
        text "hive names are letters, digits and dashes"
