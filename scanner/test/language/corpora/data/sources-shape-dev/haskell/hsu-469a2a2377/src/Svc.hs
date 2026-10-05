module UsersSvc where

import Text.Read (readMaybe)

toPort :: String -> Maybe Int
toPort raw = fmap (+ 1) (readMaybe raw)

endpointPath :: String
endpointPath = "/users/u0"
