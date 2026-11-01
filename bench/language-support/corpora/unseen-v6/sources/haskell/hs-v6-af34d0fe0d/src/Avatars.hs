{-# LANGUAGE OverloadedStrings #-}
module Avatars (main) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Lazy as TL
import Web.Scotty

avatarRoot :: FilePath
avatarRoot = "/srv/uploads/avatars/"

main :: IO ()
main = scotty 8080 $ do
  get "/avatars/:name" $ do
    name <- param "name"
    bytes <- liftIO (BL.readFile (avatarRoot ++ TL.unpack name))
    setHeader "Content-Type" "image/png"
    setHeader "Cache-Control" "public, max-age=3600"
    raw bytes
  get "/avatars" $
    json ["default.png", "robot.png", "cat.png" :: TL.Text]
