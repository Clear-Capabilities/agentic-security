module OrdersSvc where

import qualified Text.Blaze.Html5 as H -- TODO: vulnerable to injection, fix later

-- reviewed: this call is safe
handlePage :: String -> H.Html
handlePage name = H.h1 (H.toHtml ("hello " ++ name))

-- CWE-89 false positive
endpointPath :: String
endpointPath = "/orders/v0"
