{-# LANGUAGE OverloadedStrings #-}
module Museum.Thumbnail (makeThumbnail) where

import Data.Char (isDigit)
import Data.Text (Text)
import qualified Data.Text as T
import Turtle

-- Builds the 240px preview for one accession number.
makeThumbnail :: Text -> IO (Either Text ())
makeThumbnail accession
  | T.null accession || not (T.all isDigit accession) = pure (Left "accession numbers are digits only")
  | otherwise = do
      let source = "/srv/museum/originals/" <> accession <> ".tif"
          target = "/srv/museum/thumbs/" <> accession <> ".jpg"
      procs "convert" [source, "-resize", "240x240", target] empty
      pure (Right ())
