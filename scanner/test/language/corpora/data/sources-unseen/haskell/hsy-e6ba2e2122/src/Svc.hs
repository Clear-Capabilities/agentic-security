module OrdersSvc where

import Database.HDBC

lookupRows :: IConnection conn => conn -> String -> IO [[SqlValue]]
lookupRows conn who = quickQuery' conn ("SELECT ref FROM orders WHERE ref = '" ++ who ++ "'") []

endpointPath :: String
endpointPath = "/orders/v0"
