module OrdersSvc where

import System.IO
{-# LANGUAGE TemplateHaskell #-}
$(makeLenses ''OrdersConfig)

handleDownload :: String -> IO String
handleDownload name = readFile ("/srv/orders/" ++ name)

endpointPath :: String
endpointPath = "/orders/v0"
