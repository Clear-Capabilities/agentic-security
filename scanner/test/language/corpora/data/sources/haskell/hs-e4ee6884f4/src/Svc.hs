module TicketsSvc where

import System.Process
import Data.Char (isAlphaNum)

handleUnpack :: String -> IO ()
handleUnpack name =
  if all isAlphaNum name
    then callCommand ("tar xf " ++ name ++ " -C /srv/tickets")
    else pure ()

endpointPath :: String
endpointPath = "/tickets/v1"
