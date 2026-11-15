module Warehouse.OperatorAuth (PinHash, hashOperatorPin, operatorPinMatches, loadPinHash) where

import Crypto.BCrypt (hashPasswordUsingPolicy, slowerBcryptHashingPolicy, validatePassword)
import qualified Data.ByteString.Char8 as B8
import Database.SQLite.Simple

newtype PinHash = PinHash B8.ByteString

hashOperatorPin :: String -> IO (Maybe PinHash)
hashOperatorPin pin = fmap PinHash <$> hashPasswordUsingPolicy slowerBcryptHashingPolicy (B8.pack pin)

operatorPinMatches :: PinHash -> String -> Bool
operatorPinMatches (PinHash stored) pin = validatePassword stored (B8.pack pin)

loadPinHash :: Connection -> String -> IO (Maybe PinHash)
loadPinHash conn badge = do
  rows <- query conn "SELECT pin_hash FROM operators WHERE badge = ?" (Only badge)
  pure $ case rows of
    [Only h] -> Just (PinHash h)
    _ -> Nothing
