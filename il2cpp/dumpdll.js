var APP_NAME = "com.hp.castle"
var target_so = "libil2cpp.so"
var targetFunctionOffset=0x1217684 // loadAssemble
// var targetFunctionOffset = 0xD02198 
Interceptor.attach(Module.findExportByName(null , "android_dlopen_ext"), {
    onEnter: function(args) {
        var soName = args[0].readCString();
        if(soName.indexOf(APP_NAME) != -1 && soName.indexOf(target_so) != -1){
            send("android_dlopen_ext load :"+soName);
            this.hook = true;
        }
    },
    onLeave:function(retval){
            if(this.hook == true){
                do_hook();
            }
    }
});

Interceptor.attach(Module.findExportByName(null , "dlopen"), {
    onEnter: function(args) {
        var soName = args[0].readCString();
        if(soName.indexOf(APP_NAME) != -1 && soName.indexOf(target_so) != -1){
            send("dlopen load :"+soName);
            this.hook = true;
        }

    },
    onLeave:function(retval){
        if(this.hook == true){
            do_hook();
        }
    }
});


function do_hook() {

    // pb proto hook
    // var nativePointer = Module.findExportByName("libc.so", "send");   
    // Interceptor.attach(nativePointer, {
    //     onEnter: function(args){
    //   if(args[1].readUInt() == 332053247){
    //       console.log("args0:\t"+args[0]);
    //     console.log(hexdump(args[1], {length:args[2].toInt32()}));
        
    //   }
    //     }
    // });

    var module_base = Module.findBaseAddress("libil2cpp.so")
    send(module_base)
    var target = module_base.add(targetFunctionOffset)
    var path = "/data/data/"+APP_NAME+"/files/Scripts.Hotfix.out.dll"
    // var path = "/sdcard/castle/Scripts.Hotfix.out.dll"
    send("target addr:\t"+target)
    Interceptor.attach(target , 
        {
            onEnter:function(args){
                console.log("------------------------------LoadAssembly-------------------------------");
                console.log("size : "   + args[1].add(0x28).readPointer().add(0x18).readU32());
                console.log("address: " + args[1].add(0x28).readPointer().add(0x20));
                console.log(hexdump(args[1].add(0x28).readPointer().add(0x20), {length:0x28}));

                console.log(hexdump(args[1], {
                  offset: 0,
                  length: 128,
                  header: true,
                }));
                var funPointer = args[1].readPointer().add(0x1A0).readPointer();
                
                var size = args[1].add(0x28).readPointer().add(0x18).readU32();
                var address = args[1].add(0x28).readPointer().add(0x20)
                
                //文件不存在
                if(access(path) == -1){
                    
                    var file_path = path ;
                    console.log("dump:",file_path);
                    var file_handle = new File(file_path , "wb");
                    console.log(hexdump(address, {
                      offset: 0,
                      length: 128,
                      header: true,
                    }));
                    var hotfix_buffer = Memory.readByteArray(address,size);
                    file_handle.write(hotfix_buffer);
                    file_handle.flush();
                    file_handle.close();
                }
                else{
                    console.log("load hotfix ")
                    
                    var dllAddr =  args[1].add(0x28).readPointer();
                    
                    var fd = My_Open(path);
                    var fileSize = get_file_size(fd);
                    // var new_mem = Memory.alloc(fileSize+0x20);
                    var new_mem = My_Malloc(fileSize+0x20);
                    // var memPage = Process.getRangeByAddress(new_mem);
                    // console.log(memPage);
                    console.log("file size:%t",fileSize)
                    console.log("new_mem:\t"+ptr(new_mem));
                    //copy  dllHeader
                    Memory.copy(ptr(new_mem), dllAddr, 0x20)

                    // update file length
                    ptr(new_mem).add(0x18).writePointer(ptr(fileSize));
                    
                    // read new dll content
                    My_Read(fd , ptr(new_mem).add(0x20) , fileSize);
                    My_Close(fd)
                    
                    //write funcTionPtr 
                    ptr(new_mem).readPointer().add(0x1A0).writePointer(funPointer);
                    
                    console.log(hexdump(ptr(new_mem), {
                        offset: 0,
                        length: 128,
                        header: true,
                    }));

                    args[1].add(0x28).writePointer(ptr(new_mem));
                    // Memory.copy(args[1].add(0x28).readPointer().add(0x20),ptr(new_mem).add(0x20),size);		//dll内存空间替换
                    console.log(hexdump(args[1] ,{
                        offset: 0,
                        length: 128,
                        header: true,
                    }))
                    

                }
                
            },
            onLeave: function(retval) {
                console.log("ret_val:\t"+retval);
            },
        }
    )

  

    Interceptor.attach(module_base.add(0xD05964) , 
        {
            onEnter:function(args){
                console.log(args[1]);
                // console.log(hexdump(ptr(args[1]), {length:0x128}));
                // console.log(args[0].readPointer().add(0x1A0).readPointer());
                // var funPointer = args[0].readPointer().add(0x1A0).readPointer();
                // console.log(hexdump(args[0].add(0x28).readPointer().add(0x20), {length:0x28}));
                // console.log("funPointer :\t" + funPointer);
                
            },
            onLeave: function(retval) {
                console.log("sub_D05964 ret_val:\t"+retval);
            },
        }
    )
}


function My_Open(path){
    var ptr_open = Module.findExportByName("libc.so","open");
    send("ptr_open:\t"+ptr_open);
    const open = new NativeFunction(ptr_open,'int',['pointer','int']);
    var ret_val = open(Memory.allocUtf8String(path) , 0);
    return ret_val;
}

function My_Close(fd){
    var ptr_close = Module.findExportByName("libc.so","close");
    const close = new NativeFunction(ptr_close,'int',['int']);
    var ret_val = close(fd);
    return ret_val;
}

function My_Read(fd , buffer ,  size ){
    var ptr_read = Module.findExportByName("libc.so","read");
    const read = new NativeFunction(ptr_read,'ssize_t',['int','pointer','size_t']);
    var ret_val =  read(fd , buffer , size);
    return ret_val;
}

function My_Malloc(size){
    var ptr_malloc = Module.findExportByName("libc.so","malloc");
    send("ptr_mallloc:\t"+ptr_malloc);
    const malloc = new NativeFunction(ptr_malloc,'pointer',['size_t']);
    var ret_val = malloc(size)
    return ret_val;
}



function Dump(filePath,data,datalen){
    send("dump  : "+ filePath);
    var dumpfile = new File(filePath,"wb"); 
    dumpfile.write(data.readByteArray(datalen));
    dumpfile.close();
}

function access(filePath){
    
    var ptr_access = Module.findExportByName("libc.so","access");
    var func_access = new NativeFunction(ptr_access,'int',['pointer','int']);
    var ptr_filepath = Memory.allocUtf8String(filePath);
    var ret = func_access(ptr_filepath,0);
    return ret;
}

function mkdir(Path){
    var ptr_mkdir = Module.findExportByName("libc.so","mkdir");
    var func_mkdir = new NativeFunction(ptr_mkdir,'int',['pointer','int']);
    var ptr_filepath = Memory.allocUtf8String(Path);
    var ret = func_mkdir(ptr_filepath,777);
    return ret;
}

function folder_mkdirs(p){
    var p_list = p.split("/");
    var pp = "/sdcard/fridadump/lua";
    for(var i = 0;i< p_list.length  ;i++){
        pp = pp + "/" + p_list[i];
        if(access(pp) != 0){
            var x = mkdir(pp)
            send("mkdir :"+pp+"ret :" +x);
        }
    }
    
}

// frida file 对象没有read 
function read_lua(filePath){
    var ptr_open = Module.findExportByName("libc.so","open");
    const open = new NativeFunction(ptr_open,'int',['pointer','int']);

    var ptr_read = Module.findExportByName("libc.so","read");
    const read = new NativeFunction(ptr_read,'int',['int','pointer','int']);

    var ptr_close = Module.findExportByName("libc.so","close");
    const close = new NativeFunction(ptr_close,'int',['int']);

    var fd = open(Memory.allocUtf8String(filePath),0);
    var size = get_file_size(fd);
    if(size >0){
        var data = Memory.alloc(size + 5);
        if( read(fd,data,size) <0){
            console.log('[+] Unable to read DLL [!]');
            close(fd);
            return 0;
        }
        close(fd);
        return data;
    }

}

function get_file_size(fd){
    var statBuff = Memory.alloc(500);
    var fstatSymbol = Module.findExportByName('libc.so', 'fstat');
    var fstat = new NativeFunction(fstatSymbol, 'int', ['int', 'pointer']);
    if(fd > 0) {
        var ret = fstat(fd, statBuff);
        if(ret < 0) { console.log('[+] fstat --> failed [!]');
        }
    }
    var size = Memory.readS32(statBuff.add(0x30));
    if(size > 0) {
            return size;
        } else {
            return 0;
    }
}
