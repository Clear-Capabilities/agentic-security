module OrdersSvc where

import Web.Scotty
import qualified Data.ByteString.Lazy as BL
import Control.Monad.IO.Class (liftIO)

main :: IO ()
main = scotty 3000 $ post "/orders/ingest" $ do
  payload <- body
  liftIO (BL.writeFile "/var/spool/orders/inbox.dat" payload)
  text "queued"

endpointPath :: String
endpointPath = "/orders/v0"
