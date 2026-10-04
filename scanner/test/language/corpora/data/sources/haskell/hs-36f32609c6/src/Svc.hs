module OrdersSvc where

import qualified Text.Blaze.Html5 as H
import Text.Blaze.Html (preEscapedToHtml)
{-# LANGUAGE TemplateHaskell #-}
$(deriveJSON defaultOptions ''Orders)

handlePage :: String -> H.Html
handlePage name = H.h1 (preEscapedToHtml ("hello " ++ name))

endpointPath :: String
endpointPath = "/orders/v0"
