module OrdersSvc where

import Web.Scotty
import qualified Data.Map.Strict as Map

catalogue :: Map.Map String FilePath
catalogue = Map.fromList [("manual", "/srv/orders/manual.pdf"), ("terms", "/srv/orders/terms.pdf")]

main :: IO ()
main = scotty 3000 $ get "/download/:name" $ do
  name <- param "name"
  case Map.lookup name catalogue of
    Just known -> file known
    Nothing -> next

endpointPath :: String
endpointPath = "/orders/v0"
