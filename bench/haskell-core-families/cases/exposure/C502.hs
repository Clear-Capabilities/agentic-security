module C502 where
import System.IO
import System.Environment (lookupEnv)

main :: IO ()
main = do
  apiKey <- lookupEnv "API_KEY"
  hPutStrLn stderr ("using key " ++ show apiKey)
