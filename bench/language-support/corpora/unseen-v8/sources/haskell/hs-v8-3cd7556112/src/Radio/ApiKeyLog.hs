{-# LANGUAGE OverloadedStrings #-}
module Radio.ApiKeyLog (noteApiKeyUse) where

import Control.Monad.Logger (MonadLogger, logInfoN)
import Crypto.Hash (Digest, SHA256, hash)
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.Text as T

fingerprint :: ByteString -> Text
fingerprint key = T.take 12 (T.pack (show (hash key :: Digest SHA256)))

noteApiKeyUse :: (MonadLogger m) => ByteString -> Text -> m ()
noteApiKeyUse apiKey endpoint =
  logInfoN ("schedule api call " <> endpoint <> " key=" <> fingerprint apiKey)
