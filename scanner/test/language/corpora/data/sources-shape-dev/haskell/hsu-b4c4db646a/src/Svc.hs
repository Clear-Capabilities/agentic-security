module OrdersSvc where

import Data.Maybe (listToMaybe)

firstArg :: [String] -> Maybe String
firstArg = listToMaybe

endpointPath :: String
endpointPath = "/orders/u0"
