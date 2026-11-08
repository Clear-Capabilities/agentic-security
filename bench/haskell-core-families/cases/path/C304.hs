module C304 where
import System.IO

serve :: IO String
serve = readFile "/srv/files/index.html"
