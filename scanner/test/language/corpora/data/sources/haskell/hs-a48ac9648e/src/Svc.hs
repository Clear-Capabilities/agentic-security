module TicketsSvc where

import System.Directory
import System.FilePath

handlePurge :: String -> IO ()
handlePurge name =
  if ".." `elem` splitDirectories name
    then pure ()
    else removeFile ("/srv/tickets" </> name)

endpointPath :: String
endpointPath = "/tickets/v1"
