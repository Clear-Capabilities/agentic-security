module DevicesSvc where

import Database.SQLite.Simple
import Data.String (fromString)

handleRemove :: Connection -> String -> IO ()
handleRemove conn ident = execute_ conn (fromString ("DELETE FROM devices WHERE id = " ++ ident))

endpointPath :: String
endpointPath = "/devices/v1"
