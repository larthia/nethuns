#!/usr/bin/env stack
-- stack runghc --resolver lts-16.31 --package optparse-applicative --package ansi-terminal --allow-different-user --install-ghc
--

{-# LANGUAGE RecordWildCards #-}

import System.Exit
import System.FilePath.Posix
import System.Process

data Build = Build {
     optBuiltinPcapReader :: Opt 
   , optTpacketV3         :: Opt  
   , optNetmap            :: Opt  
   , optLibpcap           :: Opt  
   , optXDP               :: Opt  
}


newtype Opt = Opt Bool
               deriving (Eq)


on  = Opt True
off = Opt False 


(.|.) :: Opt -> Opt -> Opt 
(Opt a) .|. (Opt b) = Opt (a || b)
{-# INLINE (.|.) #-}
 

(.&.) :: Opt -> Opt -> Opt
(Opt a) .&. (Opt b) = Opt (a && b)
{-# INLINE (.&.) #-}


main = do
  let builds = [ Build{..} |  optBuiltinPcapReader <- [off, on] 
                           ,  optTpacketV3 	   <- [off, on]
                           ,  optNetmap    	   <- [off, on]
                           ,  optLibpcap   	   <- [off, on]
                           ,  optXDP       	   <- [off, on] 
			   ,  let (Opt filter) = optTpacketV3 .|. optNetmap .|. optLibpcap .|. optXDP
				in filter	
			   ]

  mapM_ testBuild builds


instance Show Opt where
    show (Opt True) = "ON"
    show _          = "OFF"


mkCMakeOpt :: Build -> [String]
mkCMakeOpt Build{..} = 
        [ "NETHUNS_OPT_BUILTIN_PCAP_READER"     <> "=" <> show optBuiltinPcapReader
        , "NETHUNS_OPT_TPACKET_V3"              <> "=" <> show optTpacketV3
        , "NETHUNS_OPT_NETMAP"                  <> "=" <> show optNetmap
        , "NETHUNS_OPT_LIBPCAP"                 <> "=" <> show optLibpcap
        , "NETHUNS_OPT_XDP"                     <> "=" <> show optXDP ] 


testBuild :: Build -> IO ()
testBuild build = do
  let opts = mkCMakeOpt build
  cmd "cmake" $ ["-B", "BUILD"] <> (("-D" <>) <$> (mkCMakeOpt build))
  cmd "make"    ["-C", "BUILD"]
  cmd "make"    ["-C", "BUILD", "clean"]


cmd :: FilePath -> [String] -> IO ()
cmd cmd args = do
  putStrLn $ "-> "<> (unwords $ cmd : args) 
  ec <- waitForProcess =<< spawnProcess cmd args
  case ec of
    ExitFailure n -> errorWithoutStackTrace $ "builder: " <> cmd <> " exited with code " <> show n
    _ -> return ()


