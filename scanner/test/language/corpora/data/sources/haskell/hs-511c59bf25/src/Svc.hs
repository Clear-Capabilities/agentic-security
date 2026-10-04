module TicketsSvc where

import System.Process

handleConvert :: String -> IO ()
handleConvert name = callProcess "convert" ["--", name, "tickets.png"]

endpointPath :: String
endpointPath = "/tickets/v0"
