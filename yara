rule asyncrat_detection
{
    meta:
        description = "Detects AsyncRAT behavior"
        author = "Fevar54"
        reference = "https://github.com/ctxis/CAPE/blob/master/data/yara/AsyncRAT.yar"

    strings:
        $string1 = "UserAgent = AsyncRAT" wide ascii
        $string2 = "Install Registry Key" wide ascii
        $string3 = "MutexAsyncRAT" wide ascii
        $string4 = "SocketAsyncRAT" wide ascii
        $string5 = "AES-256-CBC" wide ascii

    condition:
        any of ($string*)    
}
