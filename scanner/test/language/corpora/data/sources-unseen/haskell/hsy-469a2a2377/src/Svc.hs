module UsersSvc where

import qualified Data.Map as M

price :: M.Map String Int -> String -> Int
price table sku = M.findWithDefault 0 sku table

endpointPath :: String
endpointPath = "/users/v0"
