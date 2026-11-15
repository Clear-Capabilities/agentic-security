{-# LANGUAGE OverloadedStrings #-}
module Museum.StaffAuth (registerStaff, verifyStaff) where

import Crypto.Hash (Digest, SHA256, hash)
import Data.ByteArray.Encoding (Base (Base16), convertToBase)
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Database.Persist
import Database.Persist.Sql (SqlPersistT)
import Museum.Model

digestFor :: Text -> Text
digestFor pw = TE.decodeUtf8 (convertToBase Base16 (hash (TE.encodeUtf8 pw) :: Digest SHA256))

registerStaff :: Text -> Text -> SqlPersistT IO (Key Staff)
registerStaff login pw = insert (Staff login (digestFor pw))

verifyStaff :: Text -> Text -> SqlPersistT IO Bool
verifyStaff login pw = do
  found <- getBy (UniqueStaffLogin login)
  pure $ case found of
    Just (Entity _ s) -> staffPasswordDigest s == digestFor pw
    Nothing -> False
