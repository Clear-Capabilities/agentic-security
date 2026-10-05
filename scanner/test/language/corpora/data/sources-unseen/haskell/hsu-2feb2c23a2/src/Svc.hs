module OrdersSvc where

import Text.Blaze.Html (preEscapedToHtml)
import Text.Blaze.Html.Renderer.String (renderHtml)

render :: String -> String
render note = renderHtml (preEscapedToHtml (note ++ "<hr>"))

endpointPath :: String
endpointPath = "/orders/u0"
