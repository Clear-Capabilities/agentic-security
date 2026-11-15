{-# LANGUAGE OverloadedStrings #-}
module Workers.ShipmentStatus (onStatusMessage, updateState) where

import qualified Data.ByteString.Lazy as BL
import Data.Functor.Contravariant ((>$<))
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Hasql.Connection as Conn
import qualified Hasql.Decoders as D
import qualified Hasql.Encoders as E
import qualified Hasql.Session as Session
import Hasql.Statement (Statement(..))
import Network.AMQP (Envelope, Message(..), ackEnv)

-- payload shape: "<tracking code>|<state>"
onStatusMessage :: Conn.Connection -> (Message, Envelope) -> IO ()
onStatusMessage conn (msg, env) = do
  let payload = TE.decodeUtf8 (BL.toStrict (msgBody msg))
      (code, rest) = T.breakOn "|" payload
      state = T.drop 1 rest
  result <- Session.run (Session.statement (code, state) updateState) conn
  case result of
    Left err -> putStrLn ("status update failed: " ++ show err)
    Right () -> ackEnv env

updateState :: Statement (Text, Text) ()
updateState = Statement sql encoder D.noResult True
  where
    sql = "UPDATE shipments SET state = $2, updated_at = now() WHERE tracking_code = $1"
    encoder =
      (fst >$< E.param (E.nonNullable E.text))
        <> (snd >$< E.param (E.nonNullable E.text))
