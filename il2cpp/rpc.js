rpc.exports = {

    findmodule: function(so_name) {
        var libso = Process.findModuleByName(so_name);
        return libso;
    },
    dumpmodule: function(so_name) {
        var libso = Process.findModuleByName(so_name);
        if (libso == null) {
            return -1;
        }
        send(libso);
        Memory.protect(ptr(libso.base), libso.size, 'rwx');
        var libso_buffer = ptr(libso.base).readByteArray(libso.size);
        // libso.buffer = libso_buffer;
        return libso_buffer;
    },
    arch: function() {
        return Process.arch;
    },
    dumpmemory: function(beginAddr , endAddr){
        var buffer = ptr(beginAddr).readByteArray(endAddr-beginAddr)
        return buffer;
    },
    gmdscan: function (){
            var addrArray = Process.enumerateRanges("r--");
            for (var i = 0; i < addrArray.length; i++)
            {
                var addr = addrArray[i];
                
                if (addr.file){
                    var path = addr.file.path;
                    if(path.indexOf("global-metadata.dat")!= -1){
                        console.log("find global-metadata.dat");
                        console.log("base :"+addr.base);
                        console.log("size :"+addr.size);
                        var retBuffer =ptr(addr.base).readByteArray(addr.size);
                        console.log(hexdump(addr.base, {
                            offset: 0,
                            length: 64,
                            header: true,
                            ansi: true
                          }));
                        return retBuffer;
                    }
                    
                }
                
              
            }
    } , 
    dumpdll : function(){
        scandll();
    }
}


function scandll() {
    var dllnum = 0;
    Process.enumerateRanges('r--').forEach(function (range) {
        try {
            Memory.scan(range.base,range.size,"4D 5A 90 00",{
                onMatch:function (address, size) {
                    var dllsize = address.add(0X9C).readPointer().toInt32() + address.add(0xA0).readPointer().toInt32() + address.add(0xD4).readPointer().toInt32();
                    dllnum = dllnum + 1;
                    var file_path = "/data/data/com.hp.castle/files/" + dllnum.toString() + ".dll";
                    var file_handle = new File(file_path, "wb");
                    if (file_handle && file_handle != null) {
                        Memory.protect(ptr(address), size, 'rwx');
                        var libso_buffer = ptr(address).readByteArray(dllsize);
                        file_handle.write(libso_buffer);
                        file_handle.flush();
                        file_handle.close();
                        console.log("[dump]:" + file_path + "  [size]:" + dllsize + "\t[address]:\t"+ptr(address));
                    }
                },
                onError:function (reason) {
                    console.error("scan error :" + reason);
                },
                onComplete:function () {
                    //console.log("scan onComplete")
                }
            })

        }catch (e) {
            console.error(e)
        }


    })
}
