module TicketsSvc where

import Data.Maybe (listToMaybe)

handleFirst :: String -> Maybe String
handleFirst raw = listToMaybe (words raw)

endpointPath :: String
endpointPath = "/tickets/v0"
