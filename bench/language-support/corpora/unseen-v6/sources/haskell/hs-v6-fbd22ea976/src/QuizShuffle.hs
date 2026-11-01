{-# LANGUAGE OverloadedStrings #-}
module QuizShuffle (main) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (object, (.=))
import Data.Text (Text)
import Network.HTTP.Types (status404)
import Network.Wai.Handler.Warp (run)
import System.Random (randomRIO)
import Web.Twain

main :: IO ()
main = run 8080 $ foldr ($) (notFound missing) [ get "/quizzes/:quiz/questions" questions ]

questions :: ResponderM a
questions = do
  quiz <- pathParam "quiz"
  order <- liftIO (shuffle (bank quiz))
  send (json (object ["quiz" .= (quiz :: Text), "questions" .= order]))

bank :: Text -> [Text]
bank "haskell" = ["What is a monad?", "Name three list functions", "Explain laziness"]
bank _ = ["What is a type?", "What is a function?"]

shuffle :: [a] -> IO [a]
shuffle [] = pure []
shuffle xs = do
  i <- randomRIO (0, length xs - 1)
  let chosen = xs !! i
      rest = take i xs ++ drop (i + 1) xs
  (chosen :) <$> shuffle rest

missing :: ResponderM a
missing = send (status status404 (text "no such quiz"))
