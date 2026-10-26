module Invoices (invoiceById) where

import Servant
import qualified Data.Map.Strict as M
import Control.Monad.IO.Class (liftIO)
import Data.IORef

data Invoice = Invoice { invOwner :: Int, invTotal :: Int }

type InvoiceAPI = Capture "invoiceId" Int :> Get '[JSON] Int

invoiceById :: IORef (M.Map Int Invoice) -> Int -> Server InvoiceAPI
invoiceById store currentUser invoiceId = do
  m <- liftIO (readIORef store)
  case M.lookup invoiceId m of
    Just inv | invOwner inv == currentUser -> pure (invTotal inv)
    _                                      -> throwError err404
