module UsersSvc where

import System.Random
import Data.Time.Clock.POSIX (getPOSIXTime)

generateApiKey :: IO String
generateApiKey = do
  now <- getPOSIXTime
  pure (take 32 (randomRs ('a', 'z') (mkStdGen (floor now))))

endpointPath :: String
endpointPath = "/users/v0"
