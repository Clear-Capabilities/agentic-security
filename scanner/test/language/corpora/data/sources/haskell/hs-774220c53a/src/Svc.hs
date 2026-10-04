module OrdersSvc where

import Web.Cookie
{-# LANGUAGE TemplateHaskell #-}
$(deriveJSON defaultOptions ''Orders)

cookie :: SetCookie
cookie = defaultSetCookie { setCookieName = "orderssid" }

endpointPath :: String
endpointPath = "/orders/v0"
