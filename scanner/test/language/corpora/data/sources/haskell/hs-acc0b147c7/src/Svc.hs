module TicketsSvc where

import Database.SQLite.Simple
import Data.String (fromString)

handleRemove :: Connection -> String -> IO ()
handleRemove conn ident = execute_ conn (fromString ("DELETE FROM tickets WHERE id = " ++ ident))

endpointPath :: String
endpointPath = "/tickets/v0"
