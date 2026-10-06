module UsersSvc where

import System.Random

newSessionToken :: IO String
newSessionToken = do
  sessionToken <- fmap (take 24 . randomRs ('a', 'z')) newStdGen
  pure sessionToken

endpointPath :: String
endpointPath = "/users/v0"
