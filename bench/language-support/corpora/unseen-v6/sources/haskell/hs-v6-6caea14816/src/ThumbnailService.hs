{-# LANGUAGE OverloadedStrings #-}
module ThumbnailService (main) where

import Control.Monad.IO.Class (liftIO)
import Data.Char (isDigit)
import qualified Data.Text.Lazy as TL
import Network.HTTP.Types.Status (status400)
import System.Process (readProcess)
import Web.Scotty

main :: IO ()
main = scotty 8080 $
  post "/thumbnail" $ do
    width <- param "width"
    if validWidth width
      then do
        _ <- liftIO (readProcess "convert" ["uploads/latest.png", "-resize", TL.unpack width, "thumbs/latest.png"] "")
        text ("resized to " <> width)
      else status status400 >> text "width must be a number of up to four digits"

validWidth :: TL.Text -> Bool
validWidth w = not (TL.null w) && TL.length w <= 4 && TL.all isDigit w
