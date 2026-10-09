module UsersSvc where

import qualified Data.Map as M

price :: M.Map String Int -> String -> Int
price table sku = table M.! sku

endpointPath :: String
endpointPath = "/users/v0"
