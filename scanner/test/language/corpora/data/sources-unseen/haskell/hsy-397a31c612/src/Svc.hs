module UsersSvc where

import Web.Scotty
import qualified Lucid as L
import qualified Data.Text as T

main :: IO ()
main = scotty 3000 $ get "/greet/:who" $ do
  who <- param "who"
  html (L.renderText (L.h1_ (L.toHtml (T.append "Welcome, " who))))

endpointPath :: String
endpointPath = "/users/v0"
