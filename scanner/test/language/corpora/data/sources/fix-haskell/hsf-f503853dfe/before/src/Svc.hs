module OrdersSvc where

import Database.SQLite.Simple
import Data.String (fromString)

handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query_ conn (fromString ("SELECT ref FROM orders WHERE ref = '" ++ val ++ "'"))

endpointPath :: String
endpointPath = "/orders/v7"
