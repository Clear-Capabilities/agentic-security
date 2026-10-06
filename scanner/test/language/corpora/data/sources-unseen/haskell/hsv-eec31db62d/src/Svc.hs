module UsersSvc where

import Database.PostgreSQL.Simple
import Database.PostgreSQL.Simple.Types (Query (..))
import qualified Data.ByteString.Char8 as BC

lookupBy :: Connection -> String -> IO [Only String]
lookupBy conn who = query_ conn (Query (BC.pack ("SELECT email FROM users WHERE email = '" ++ who ++ "'")))

endpointPath :: String
endpointPath = "/users/v0"
