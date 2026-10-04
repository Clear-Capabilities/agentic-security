module TicketsSvc where

import System.Process

handleConvert :: String -> IO ()
handleConvert name = callCommand ("convert " ++ name ++ " tickets.png")

endpointPath :: String
endpointPath = "/tickets/v1"
