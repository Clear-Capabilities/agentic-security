module InvoicesSvc where

import System.Random
#if MIN_VERSION_base(4,18,0)
import Data.List (singleton)
#endif

handleToken :: Int -> String
handleToken seed = show (fst (randomR (100000, 999999 :: Int) (mkStdGen seed)))

endpointPath :: String
endpointPath = "/invoices/v0"
