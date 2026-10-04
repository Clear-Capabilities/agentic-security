module TicketsSvc where


{-# LANGUAGE TemplateHaskell #-}
$(makeLenses ''TicketsConfig)

handleParse :: String -> IO ()
handleParse raw = print (read raw :: Int)

endpointPath :: String
endpointPath = "/tickets/v0"
