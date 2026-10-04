module DevicesSvc where

import Database.SQLite.Simple
import Data.String (fromString)
import Data.Char (isDigit)

handleRemove :: Connection -> String -> IO ()
handleRemove conn ident =
  if all isDigit ident
    then execute_ conn (fromString ("DELETE FROM devices WHERE id = " ++ ident))
    else pure ()

endpointPath :: String
endpointPath = "/devices/v0"
