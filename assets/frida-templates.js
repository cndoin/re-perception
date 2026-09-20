/*
 * frida-templates.js —— 常用 Hook 模板（按需取用，改完再跑）
 *
 * 用法：
 *   frida -f <目标> -l frida-templates.js --no-pause      # spawn 模式（能抓到最早的行为）
 *   frida -n <进程名> -l frida-templates.js               # attach 模式
 *   frida -U -f <包名> -l frida-templates.js              # Android USB
 *
 * 合规提醒：只对自己拥有或书面授权的目标使用。
 */

// ============================================================
// 1. Native：打印函数调用的参数与返回值（最常用）
// ============================================================
const TARGET_FN = "strcmp";   // ← 改成你的目标函数名

Interceptor.attach(Module.getExportByName(null, TARGET_FN), {
  onEnter(args) {
    // C 字符串参数：args[0].readCString()
    // 指针 → 十六进制：args[0]      整数：args[0].toInt32()
    // 读内存：args[0].readByteArray(64)   读写结构体：args[0].readPointer()
    console.log(`[${TARGET_FN}] enter arg0=${args[0]} arg1=${args[1]}`);
    this.arg0 = args[0];
  },
  onLeave(retval) {
    console.log(`[${TARGET_FN}] leave retval=${retval}` +
                (this.arg0 ? "  arg0=" + this.arg0.readCString() : ""));
  }
});

// ============================================================
// 2. Native：按模块 + 偏移 Hook（无导出符号时用）
// ============================================================
// const base = Module.findBaseAddress("libtarget.so");
// Interceptor.attach(base.add(0x12345), {
//   onEnter(args) { console.log("hit @", args[0], args[1]); }
// });

// ============================================================
// 3. Native：替换实现（改返回值 / 短路校验）
// ============================================================
// Interceptor.replace(Module.getExportByName(null, "check_license"),
//   new NativeCallback(() => 1, "int", []));

// ============================================================
// 4. Native：一次性打印调用栈（定位是谁调用了这个函数）
// ============================================================
// Interceptor.attach(Module.getExportByName(null, TARGET_FN), {
//   onEnter() {
//     console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
//       .map(DebugSymbol.fromAddress).join("\n"));
//   }
// });

// ============================================================
// 5. 抓解密前后的明文：Hook 加密/传输边界
//    这是「运行时必然解密」思想的直接落地
// ============================================================
function hexdump(ptr, len) {
  try {
    if (!ptr) return "<null>";
    const buf = ptr.readByteArray(Math.min(len, 256));
    if (!buf) return "<empty>";
    return Array.from(new Uint8Array(buf))
      .map(b => b.toString(16).padStart(2, "0")).join(" ");
  } catch (e) {
    return "<unreadable>";
  }
}

// OpenSSL：SSL_write（明文 → 密文） / SSL_read（密文 → 明文）
["SSL_write", "SSL_read"].forEach(name => {
  const p = Module.findExportByName(null, name);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) {
      // int SSL_write(SSL *ssl, const void *buf, int num)
      this.buf = args[1];
      this.len = args[2].toInt32();
    },
    onLeave(retval) {
      const n = retval.toInt32();
      if (n > 0 && this.buf) {
        console.log(`\n[${name}] ${n} bytes\n${hexdump(this.buf, n)}`);
        try { console.log("  as utf8: " + this.buf.readUtf8String(Math.min(n, 256))); } catch (e) {}
      }
    }
  });
});

// Windows：CryptEncrypt / CryptDecrypt
// Linux/macOS：也可以 Hook libc 的 write/send/recv

// ============================================================
// 6. Android：Hook Java 方法
// ============================================================
if (Java.available) {
  Java.perform(() => {
    // 6.1 枚举已加载的类（按关键字找目标）
    // Java.enumerateLoadedClasses({
    //   onMatch(n) { if (n.includes("login") || n.includes("Auth")) console.log(n); },
    //   onComplete() {}
    // });

    // 6.2 Hook 具体方法：打印参数与返回值
    // const CLS = Java.use("com.example.app.LoginManager");
    // CLS.login.overload("java.lang.String", "java.lang.String").implementation = function (u, p) {
    //   console.log(`[login] user=${u} pass=${p}`);
    //   const ret = this.login(u, p);
    //   console.log(`[login] => ${ret}`);
    //   return ret;
    // };

    // 6.3 Hook 构造函数
    // const Req = Java.use("com.example.app.net.Request");
    // Req.$init.implementation = function (a, b) {
    //   console.log("[Request] ctor", a, b);
    //   return this.$init(a, b);
    // };

    // 6.4 主动调用静态方法
    // const Util = Java.use("com.example.app.Util");
    // console.log(Util.decrypt("xxxx"));

    // 6.5 打印所有类的所有方法（探索阶段）
    // Java.enumerateLoadedClasses({
    //   onMatch(c) {
    //     try {
    //       Java.use(c).class.getDeclaredMethods().forEach(m => console.log(c + "." + m.getName()));
    //     } catch (e) {}
    //   }, onComplete() {}
    // });
  });
}

// ============================================================
// 7. iOS：Hook ObjC 方法
// ============================================================
if (ObjC.available) {
  // 7.1 追踪某个类的所有方法调用
  // const hook = ObjC.classes.NSURLSession;   // ← 改成目标类
  // for (const m of hook.$ownMethods) {
  //   try {
  //     const impl = hook[m].implementation;
  //     Interceptor.attach(impl, { onEnter() { console.log("-[NSURLSession " + m + "]"); } });
  //   } catch (e) {}
  // }

  // 7.2 Hook 指定方法
  // Interceptor.attach(ObjC.classes.LoginManager["- loginWithUser:password:"].implementation, {
  //   onEnter(args) {
  //     console.log("user:", new ObjC.Object(args[2]).toString());
  //     console.log("pass:", new ObjC.Object(args[3]).toString());
  //   }
  // });

  // 7.3 枚举所有类（按关键字）
  // for (const name in ObjC.classes) {
  //   if (name.includes("Auth")) console.log(name);
  // }
}

// ============================================================
// 8. 内存：扫描 DEX 魔数（Android 脱壳的核心思路）
// ============================================================
// Process.enumerateRanges("r--").forEach(r => {
//   Memory.scan(r.base, r.size, "64 65 78 0a 30 33 35 00", {
//     onMatch(addr, size) {
//       console.log("DEX @ " + addr + " size~" + addr.readUInt());
//       // 从 addr 处按 header 里的 file_size 读出完整 DEX 并 send() 回主机
//     },
//     onComplete() {}
//   });
// });

// ============================================================
// 9. 绕过常见反调试（仅自有/授权目标）
// ============================================================
// // Windows: IsDebuggerPresent 恒返回 0
// const idp = Module.findExportByName("kernel32.dll", "IsDebuggerPresent");
// if (idp) Interceptor.replace(idp, new NativeCallback(() => 0, "int", []));
//
// // Linux: ptrace(PTRACE_TRACEME) 恒返回 0
// const pt = Module.findExportByName(null, "ptrace");
// if (pt) Interceptor.replace(pt, new NativeCallback(() => 0, "long", ["int", "int", "pointer", "pointer"]));
