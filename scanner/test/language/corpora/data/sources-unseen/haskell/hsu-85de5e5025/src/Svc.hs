module UsersSvc where

import Text.Blaze.Html (toHtml)
import Text.Blaze.Html.Renderer.String (renderHtml)

render :: String -> String
render note = renderHtml (toHtml (note ++ " - users"))

endpointPath :: String
endpointPath = "/users/u0"
