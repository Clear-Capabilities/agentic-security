{-# LANGUAGE OverloadedStrings #-}
module Orchard.Imagery.Unpack (startUnpackWorker) where

import Network.AMQP
import qualified Codec.Compression.GZip as GZip
import qualified Data.ByteString.Lazy as BL
import Data.Int (Int64)

maxTileBytes :: Int64
maxTileBytes = 32 * 1024 * 1024

startUnpackWorker :: Channel -> (BL.ByteString -> IO ()) -> IO ()
startUnpackWorker chan storeTile = do
  _ <- declareQueue chan newQueue { queueName = "imagery.tiles" }
  _ <- consumeMsgs chan "imagery.tiles" Ack (handleTile storeTile)
  pure ()

handleTile :: (BL.ByteString -> IO ()) -> (Message, Envelope) -> IO ()
handleTile storeTile (msg, env) = do
  let inflated = BL.take (maxTileBytes + 1) (GZip.decompress (msgBody msg))
  if BL.length inflated > maxTileBytes
    then rejectEnv env False
    else do
      storeTile inflated
      ackEnv env
