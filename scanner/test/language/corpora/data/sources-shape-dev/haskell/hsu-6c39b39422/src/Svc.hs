module OrdersSvc where

import Text.Read (readMaybe)

toPort :: String -> Maybe Int
toPort raw = fmap (+ 1) (readMaybe raw)

endpointPath :: String
endpointPath = "/orders/u0"
