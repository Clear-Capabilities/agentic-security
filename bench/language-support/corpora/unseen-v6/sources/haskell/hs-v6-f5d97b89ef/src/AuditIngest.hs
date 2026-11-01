{-# LANGUAGE DeriveGeneric, OverloadedStrings #-}
module AuditIngest (main) where

import Data.Aeson (FromJSON, decodeStrict)
import Data.Functor.Contravariant ((>$<))
import Data.Text (Text)
import GHC.Generics (Generic)
import qualified Hasql.Connection as Connection
import qualified Hasql.Decoders as D
import qualified Hasql.Encoders as E
import qualified Hasql.Session as Session
import Hasql.Statement (Statement(..))
import Kafka.Consumer

data AuditEvent = AuditEvent { actor :: Text, action :: Text, subject :: Text }
  deriving (Show, Generic)
instance FromJSON AuditEvent

insertEvent :: Statement AuditEvent ()
insertEvent = Statement "INSERT INTO audit_log (actor, action, subject) VALUES ($1, $2, $3)" encoder D.noResult True
  where
    encoder = (actor >$< E.param (E.nonNullable E.text))
           <> (action >$< E.param (E.nonNullable E.text))
           <> (subject >$< E.param (E.nonNullable E.text))

main :: IO ()
main = do
  acquired <- Connection.acquire "host=localhost dbname=audit"
  created <- newConsumer (brokersList ["localhost:9092"] <> groupId "audit-ingest") (topics ["audit-events"])
  case (acquired, created) of
    (Right conn, Right consumer) -> loop conn consumer
    _ -> putStrLn "could not start the audit consumer"
  where
    loop conn consumer = do
      polled <- pollMessage consumer (Timeout 1000)
      case polled of
        Right record | Just event <- crValue record >>= decodeStrict -> do
          _ <- Session.run (Session.statement event insertEvent) conn
          loop conn consumer
        _ -> loop conn consumer
