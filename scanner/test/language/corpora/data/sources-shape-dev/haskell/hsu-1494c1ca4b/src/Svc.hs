module UsersSvc where

import Data.Maybe (listToMaybe)

firstArg :: [String] -> Maybe String
firstArg = listToMaybe

endpointPath :: String
endpointPath = "/users/u0"
