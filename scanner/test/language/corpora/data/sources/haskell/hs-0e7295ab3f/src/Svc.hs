module DevicesSvc where

import Database.SQLite.Simple
import Data.String (fromString)

handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query_ conn (fromString ("SELECT serial FROM devices WHERE serial = '" ++ val ++ "'"))

endpointPath :: String
endpointPath = "/devices/v0"
