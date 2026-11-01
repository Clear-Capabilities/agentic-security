{-# LANGUAGE OverloadedStrings #-}
module FeaturedPicks (picksApp) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Text as T
import Database.SQLite.Simple
import System.Random (randomRIO)
import Web.Spock

data Product = Product { productSku :: Text, productTitle :: Text }

instance FromRow Product where
  fromRow = Product <$> field <*> field

picksApp :: Connection -> SpockM () () () ()
picksApp conn =
  get "home/featured" $ do
    products <- liftIO (query_ conn "SELECT sku, title FROM products WHERE featured = 1")
    chosen <- liftIO (pickSome 3 products)
    text (T.unlines (map productTitle chosen))

pickSome :: Int -> [a] -> IO [a]
pickSome 0 _  = pure []
pickSome _ [] = pure []
pickSome n xs = do
  i <- randomRIO (0, length xs - 1)
  let (before, after) = splitAt i xs
  case after of
    (x:rest) -> (x :) <$> pickSome (n - 1) (before ++ rest)
    []       -> pure []
