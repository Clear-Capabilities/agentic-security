module OrdersSvc where

import System.Random
import Data.Word (Word64)

session :: IO Word64
session = do
  g <- newStdGen
  pure (fst (random g))

endpointPath :: String
endpointPath = "/orders/u0"
