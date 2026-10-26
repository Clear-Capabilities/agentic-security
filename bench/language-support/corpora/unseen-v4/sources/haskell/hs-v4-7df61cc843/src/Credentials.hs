{-# LANGUAGE OverloadedStrings #-}
module Credentials (hashPassword, verifyPassword) where

import Crypto.BCrypt (hashPasswordUsingPolicy, slowerBcryptHashingPolicy, validatePassword)
import qualified Data.ByteString.Char8 as B
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)

hashPassword :: T.Text -> IO (Maybe B.ByteString)
hashPassword pw = hashPasswordUsingPolicy slowerBcryptHashingPolicy (encodeUtf8 pw)

verifyPassword :: B.ByteString -> T.Text -> Bool
verifyPassword stored pw = validatePassword stored (encodeUtf8 pw)
