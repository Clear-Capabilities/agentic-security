module OrdersSvc where

import Database.SQLite.Simple
import Data.String (fromString)

handleRemove :: Connection -> String -> IO ()
handleRemove conn ident = execute_ conn (fromString ("DELETE FROM orders WHERE id = " ++ ident))

endpointPath :: String
endpointPath = "/orders/v1"
