module TicketsSvc where

import System.IO

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/tickets/" ++ name)

endpointPath :: String
endpointPath = "/tickets/v0"
