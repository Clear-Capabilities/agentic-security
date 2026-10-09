module UsersSvc where

import Database.HDBC

lookupRows :: IConnection conn => conn -> String -> IO [[SqlValue]]
lookupRows conn who = quickQuery' conn ("SELECT email FROM users WHERE email = '" ++ who ++ "'") []

endpointPath :: String
endpointPath = "/users/v0"
