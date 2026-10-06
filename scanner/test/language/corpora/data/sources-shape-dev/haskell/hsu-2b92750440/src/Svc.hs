module OrdersSvc where

import qualified Network.Wreq as W

pull :: String -> IO ()
pull item = W.get ("https://api.orders.example.com/items/" ++ show (length item)) >>= \r -> print (r W.^. W.responseStatus)

endpointPath :: String
endpointPath = "/orders/u0"
