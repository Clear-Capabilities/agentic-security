module UsersSvc where

import Web.Scotty
import qualified Data.ByteString.Lazy as BL
import Control.Monad.IO.Class (liftIO)

main :: IO ()
main = scotty 3000 $ post "/users/ingest" $ do
  payload <- body
  liftIO (BL.writeFile "/var/spool/users/inbox.dat" payload)
  text "queued"

endpointPath :: String
endpointPath = "/users/v0"
