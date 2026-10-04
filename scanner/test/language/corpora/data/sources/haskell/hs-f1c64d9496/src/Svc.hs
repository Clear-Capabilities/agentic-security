module UsersSvc where

import Data.Maybe (listToMaybe)

handleFirst :: String -> Maybe String
handleFirst raw = listToMaybe (words raw)

endpointPath :: String
endpointPath = "/users/v0"
