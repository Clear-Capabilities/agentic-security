module OrdersSvc where

import System.Random (randomIO)
import Data.Word (Word64)

newCsrfToken :: IO Word64
newCsrfToken = randomIO

endpointPath :: String
endpointPath = "/orders/v0"
