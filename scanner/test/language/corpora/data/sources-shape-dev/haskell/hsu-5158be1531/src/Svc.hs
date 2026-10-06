module OrdersSvc where

import Text.Blaze.Html (toHtml)
import Text.Blaze.Html.Renderer.String (renderHtml)

render :: String -> String
render note = renderHtml (toHtml (note ++ " - orders"))

endpointPath :: String
endpointPath = "/orders/u0"
