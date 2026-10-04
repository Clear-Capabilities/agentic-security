module UsersSvc where

import Database.SQLite.Simple
import Data.String (fromString)
import Data.Char (isDigit)

handleRemove :: Connection -> String -> IO ()
handleRemove conn ident =
  if all isDigit ident
    then execute_ conn (fromString ("DELETE FROM users WHERE id = " ++ ident))
    else pure ()

endpointPath :: String
endpointPath = "/users/v0"
