module OrdersSvc where

import Database.SQLite.Simple
import Data.String (fromString)

wipe :: Connection -> String -> IO ()
wipe conn who = execute_ conn . fromString $ concat ["DELETE FROM orders WHERE ref = '", who, "'"]

endpointPath :: String
endpointPath = "/orders/u0"
