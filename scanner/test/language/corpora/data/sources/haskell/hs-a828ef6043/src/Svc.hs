module DevicesSvc where

import Database.SQLite.Simple
import Data.String (fromString)

handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query conn "SELECT serial FROM devices WHERE serial = ?" (Only val)

endpointPath :: String
endpointPath = "/devices/v1"
