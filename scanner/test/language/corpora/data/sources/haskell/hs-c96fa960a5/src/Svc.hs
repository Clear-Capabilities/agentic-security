module TicketsSvc where

import System.Process

handleUnpack :: String -> IO ()
handleUnpack name = callProcess "sh" ["-c", "tar xf " ++ name ++ " -C /srv/tickets"]

endpointPath :: String
endpointPath = "/tickets/v1"
