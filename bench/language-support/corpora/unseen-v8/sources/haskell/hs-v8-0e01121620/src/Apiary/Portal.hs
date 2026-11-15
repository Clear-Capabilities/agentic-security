module Apiary.Portal (checkMemberPassword, setMemberPassword) where

import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Digest.Pure.SHA (sha1, showDigest)
import Database.SQLite.Simple

saltedDigest :: String -> String -> String
saltedDigest salt pw = showDigest (sha1 (BL.pack (salt ++ ":" ++ pw)))

setMemberPassword :: Connection -> Int -> String -> String -> IO ()
setMemberPassword conn memberId salt pw =
  execute conn "UPDATE members SET salt = ?, pw_digest = ? WHERE id = ?" (salt, saltedDigest salt pw, memberId)

checkMemberPassword :: Connection -> Int -> String -> IO Bool
checkMemberPassword conn memberId pw = do
  rows <- query conn "SELECT salt, pw_digest FROM members WHERE id = ?" (Only memberId)
  pure $ case rows of
    [(salt, digest)] -> saltedDigest salt pw == digest
    _ -> False
