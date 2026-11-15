{-# LANGUAGE OverloadedStrings #-}
module Ferry.ResetToken (resetLink) where

import qualified Data.ByteString.Base16 as B16
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import System.Entropy (getEntropy)

resetLink :: Text -> IO Text
resetLink bookingRef = do
  token <- getEntropy 24
  pure ("https://book.ferry.example/reset/" <> bookingRef <> "/" <> TE.decodeUtf8 (B16.encode token))
