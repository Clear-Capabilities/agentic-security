{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators #-}
module Orchestra.ConcertAdmin (ConcertAdminAPI, Manager (..), concertAdminServer, managerCheck) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import Data.Text.Encoding.Error (lenientDecode)
import Servant

newtype Manager = Manager { managerName :: Text }

type ConcertAdminAPI =
  BasicAuth "orchestra-management" Manager :> "concerts" :> Capture "concert" Int :> DeleteNoContent

concertAdminServer :: (Text -> Int -> IO Bool) -> Server ConcertAdminAPI
concertAdminServer cancel mgr concertId = do
  done <- liftIO (cancel (managerName mgr) concertId)
  if done then pure NoContent else throwError err404

managerCheck :: (Text -> Text -> IO (Maybe Manager)) -> BasicAuthCheck Manager
managerCheck lookupManager = BasicAuthCheck $ \(BasicAuthData u p) -> do
  let decode = TE.decodeUtf8With lenientDecode
  r <- lookupManager (decode u) (decode p)
  pure (maybe Unauthorized Authorized r)
