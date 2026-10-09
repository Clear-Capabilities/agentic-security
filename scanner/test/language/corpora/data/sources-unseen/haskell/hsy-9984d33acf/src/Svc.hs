module UsersSvc where

import Network.HTTP.Req
import qualified Data.Text as T

fetchDoc :: T.Text -> IO ()
fetchDoc docId = runReq defaultHttpConfig $ do
  _ <- req GET (https "docs.users.example.com" /: "v1" /: docId) NoReqBody ignoreResponse mempty
  pure ()

endpointPath :: String
endpointPath = "/users/v0"
