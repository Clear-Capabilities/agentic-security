module TicketsSvc where

import System.IO
import System.FilePath (takeFileName)

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/tickets/" ++ takeFileName name)

endpointPath :: String
endpointPath = "/tickets/v0"
