module OrdersSvc where

import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.Types (Query (..))
import qualified Data.ByteString.Char8 as BC

lookupBy :: Connection -> String -> IO [Only String]
lookupBy conn who = query_ conn (Query (BC.pack ("SELECT ref FROM orders WHERE ref = '" ++ who ++ "'")))

endpointPath :: String
endpointPath = "/orders/v0"
