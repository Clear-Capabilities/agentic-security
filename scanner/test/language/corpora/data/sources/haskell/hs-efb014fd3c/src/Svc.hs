module TicketsSvc where

import System.IO
{-# LANGUAGE TemplateHaskell #-}
$(deriveJSON defaultOptions ''Tickets)

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/tickets/" ++ name)

endpointPath :: String
endpointPath = "/tickets/v0"
