module TicketsSvc where

import Database.SQLite.Simple
import Data.String (fromString)

handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query conn "SELECT title FROM tickets WHERE title = ?" (Only val)

endpointPath :: String
endpointPath = "/tickets/v1"
