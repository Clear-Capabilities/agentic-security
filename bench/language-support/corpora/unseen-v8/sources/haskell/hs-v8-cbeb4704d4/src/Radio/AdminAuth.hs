module Radio.AdminAuth (adminPasswordOk, storeAdminPassword) where

import Crypto.Scrypt (EncryptedPass (..), Pass (..), defaultParams, encryptPassIO, verifyPass')
import qualified Data.ByteString.Char8 as B8
import Database.MySQL.Simple

storeAdminPassword :: Connection -> String -> String -> IO ()
storeAdminPassword conn login pw = do
  EncryptedPass enc <- encryptPassIO defaultParams (Pass (B8.pack pw))
  _ <- execute conn "UPDATE station_admins SET pw = ? WHERE login = ?" (enc, login)
  pure ()

adminPasswordOk :: Connection -> String -> String -> IO Bool
adminPasswordOk conn login pw = do
  rows <- query conn "SELECT pw FROM station_admins WHERE login = ?" (Only login)
  pure $ case rows of
    [Only enc] -> verifyPass' (Pass (B8.pack pw)) (EncryptedPass enc)
    _ -> False
