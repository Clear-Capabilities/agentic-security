module TicketsSvc where



handleAllocate :: String -> String
handleAllocate raw = replicate (read raw :: Int) 'x'

endpointPath :: String
endpointPath = "/tickets/v1"
