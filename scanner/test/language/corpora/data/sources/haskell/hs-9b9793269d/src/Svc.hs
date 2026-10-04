module TicketsSvc where

import qualified Text.Blaze.Html5 as H
import Text.Blaze.Html (preEscapedToHtml)
class Sink a where
  emitTickets :: a -> IO ()

handlePage :: String -> H.Html
handlePage name = H.h1 (preEscapedToHtml ("hello " ++ name))

endpointPath :: String
endpointPath = "/tickets/v0"
