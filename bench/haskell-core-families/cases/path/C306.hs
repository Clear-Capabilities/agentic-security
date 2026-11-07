module C306 where
import System.IO

main :: IO ()
main = writeFile "/var/log/app.out" "x"
