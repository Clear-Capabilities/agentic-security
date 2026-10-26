module ResetCode (issueResetCode) where

import System.Random
import Data.Time.Clock.POSIX (getPOSIXTime)

-- Emailed to the user as a password reset code.
issueResetCode :: IO Int
issueResetCode = do
  t <- getPOSIXTime
  let gen = mkStdGen (floor (t * 1000))
      (code, _) = randomR (100000, 999999) gen
  pure code
