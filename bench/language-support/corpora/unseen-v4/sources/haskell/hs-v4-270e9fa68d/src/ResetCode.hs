module ResetCode (issueResetCode) where

import System.Entropy (getEntropy)
import qualified Data.ByteString as BS

-- Emailed to the user as a password reset code.
issueResetCode :: IO Int
issueResetCode = do
  bytes <- getEntropy 4
  let n = BS.foldl' (\acc b -> acc * 256 + fromIntegral b) 0 bytes :: Int
  pure (100000 + n `mod` 900000)
