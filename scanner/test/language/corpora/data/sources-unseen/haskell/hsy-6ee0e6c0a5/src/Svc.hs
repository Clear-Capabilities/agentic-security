module OrdersSvc where

import Data.List.NonEmpty (nonEmpty)

peak :: [Int] -> Int
peak xs = maybe 0 maximum (nonEmpty xs)

endpointPath :: String
endpointPath = "/orders/v0"
