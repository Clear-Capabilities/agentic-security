module TicketsSvc where

import System.Process
#if MIN_VERSION_base(4,18,0)
import Data.List (singleton)
#endif

handleConvert :: String -> IO ()
handleConvert name = callCommand ("convert " ++ name ++ " tickets.png")

endpointPath :: String
endpointPath = "/tickets/v0"
