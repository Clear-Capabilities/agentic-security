module UsersSvc where

import Text.Read (readMaybe)
import Data.Maybe (fromMaybe)

parseCount :: String -> Int
parseCount s = fromMaybe 0 (readMaybe s)

endpointPath :: String
endpointPath = "/users/v0"
