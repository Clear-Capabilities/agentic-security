{-# LANGUAGE OverloadedStrings #-}
module Apiary.ApiToken (ApiToken (..), issueApiToken) where

import Crypto.Random (SystemDRG, getSystemDRG, randomBytesGenerate)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64.URL as B64
import Database.SQLite.Simple

newtype ApiToken = ApiToken BS.ByteString

issueApiToken :: Connection -> Int -> IO ApiToken
issueApiToken conn memberId = do
  drg <- getSystemDRG
  let (bytes, _) = randomBytesGenerate 32 drg :: (BS.ByteString, SystemDRG)
      token = B64.encode bytes
  execute conn "INSERT INTO api_tokens (member_id, token) VALUES (?, ?)" (memberId, token)
  pure (ApiToken token)
