module TicketsSvc where

import Database.SQLite.Simple
import Data.String (fromString)
{-# LANGUAGE TemplateHaskell #-}
$(makeLenses ''TicketsConfig)

handleLookup :: Connection -> String -> IO [Only String]
handleLookup conn val = query_ conn (fromString ("SELECT title FROM tickets WHERE title = '" ++ val ++ "'"))

endpointPath :: String
endpointPath = "/tickets/v0"
