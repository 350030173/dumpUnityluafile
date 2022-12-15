

//
//get_self_process_name()获取当前运行进程包名
//参考：https://github.com/lasting-yang/frida_dump/blob/master/dump_dex_class.js
function get_self_process_name()
{
    var openPtr = Module.getExportByName('libc.so', 'open');
    var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

    var readPtr = Module.getExportByName("libc.so", "read");
    var read = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);

    var closePtr = Module.getExportByName('libc.so', 'close');
    var close = new NativeFunction(closePtr, 'int', ['int']);

    var path = Memory.allocUtf8String("/proc/self/cmdline");
    var fd = open(path, 0);
    if (fd != -1)
    {
        var buffer = Memory.alloc(0x1000);
        var result = read(fd, buffer, 0x1000);
        close(fd);
        result = ptr(buffer).readCString();
        return result;
    }

    return "-1";
}



function hook_dlopen()
{
    var is_can_hook = false;
    Interceptor.attach(Module.findExportByName(null, "dlopen"),
        {
            onEnter: function (args)
            {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null)
                {
                    var path = ptr(pathptr).readCString();
                    //console.log("dlopen:", path);
                    if (path.indexOf(soName) >= 0)
                    {
                        this.is_can_hook = true;
                        console.log("\n" + soName + "_path:", path);

                    }
                }
            },
            onLeave: function (retval)
            {
                if (this.is_can_hook)
                {
                    dumpUnityLua();
                    console.log("dlopen finish...");
                }
            }
        }
    );

    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args)
            {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null)
                {
                    var path = ptr(pathptr).readCString();
                    //console.log("android_dlopen_ext:", path);

                    if (path.indexOf(soName) >= 0)
                    {
                        this.is_can_hook = true;
                        console.log("\n" + soName + "_path:", path);
                    }
                }
            },
            onLeave: function (retval)
            {
                if (this.is_can_hook)
                {
                    dumpUnityLua();
                    console.log("android_dlopen_ext  finish...");
                }
            }
        }
    );
}




//写入 lua 文件
function modifyUnityLua()
{
    Java.perform(function ()
    {
        console.log("modifyUnityLua...");

        var moduleBaseAddress = Module.getBaseAddress("libil2cpp.so");
        var nativePointer = moduleBaseAddress.add(luaL_loadbuffer);
        console.log("==nativePointer", nativePointer);
        Interceptor.attach(nativePointer,
            {
                onEnter: function (args)
                {
                    var size = args[2].add(is32).toInt32();
                    var name = args[3].add(is32).readUtf16String();
                    console.log("fileSize: " + size);
                    console.log("fileName: " + name);
                    if (name.indexOf("PlayerDataManager") >= 0)
                    {
                        //打印出想改的文件的字节码，打印出来后，复制到 icyberchef ,转换为16进制码，
                        //再保存到010，再修改，注意字节码长度要一样，增加或删掉的字节码会导致文件长度不一样
                        //可以利用里面的注释补齐字节码
                        /*console.log(hexdump(args[1].add(0x10),
                           {
                               offset: 0,
                               length: size,
                               header: true,
                               ansi: true
                           }
                       )); */
                        //需要保证写入的文件和原文件的长度必须一致，否则可能出错
                        //也就是 参数中的size ，和写入的 mybuff 长度必须一致
                        Memory.writeByteArray(args[1].add(0x10), mybuff);
                    }

                },
                onLeave: function (retval)
                {

                }
            }
        );
    }
    );
}

//dump lua 文件
function dumpUnityLua()
{
    Java.perform(function ()
    {
        console.log("dumpUnityLua...");

        var moduleBaseAddress = Module.getBaseAddress("libil2cpp.so");
        var nativePointer = moduleBaseAddress.add(luaL_loadbuffer);
        console.log("==nativePointer", nativePointer);
        Interceptor.attach(nativePointer,
            {
                onEnter: function (args)
                {
                    var size = args[2].add(is32).toInt32();//如果游戏是64位的，这里可能要加0x10
                    var name = args[3].add(is32).readUtf16String();//如果游戏是64位的，这里可能要加0x10
                    console.log("size: " + size);
                    console.log("name: " + name);
                    if (name.indexOf("/") >= 0)
                    {
                        name = name.replace(/\//g, "_");//文件名带有正斜杠，替换为下划线
                    }
                    var file = new File("/sdcard/Android/data/" + get_self_process_name() + "/files/" + name, "wb");
                    file.write(Memory.readByteArray(args[1].add(0xc), size));
                    file.flush();
                    file.close();
                },
                onLeave: function (retval)
                {

                }
            }
        );
    }
    );
}

/**

unity中hook的函数
// Namespace: LuaInterface
public class LuaDLL // TypeDefIndex: 5749
public static int luaL_loadbuffer(IntPtr luaState, byte[] buff, int size, string name); // 0x127E5DC

*/

var soName = "libil2cpp.so"
var luaL_loadbuffer = 0x127E5DC
//重新写入的文件流
var mybuff = [45, 45, 91, 91, 10, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61];
var is32 = 0xc;//游戏32位写0xc, 游戏64位写0x14


setImmediate(hook_dlopen);
