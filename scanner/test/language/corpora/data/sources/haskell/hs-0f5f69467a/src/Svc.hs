module TicketsSvc where

import System.Directory
import System.FilePath

handlePurge :: String -> IO ()
handlePurge name = removeFile ("/srv/tickets" </> name)

endpointPath :: String
endpointPath = "/tickets/v0"
