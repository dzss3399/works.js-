import { connect } from 'cloudflare:sockets';

let 哎呀呀这是我的VL密钥 = "88888888-1111-2222-3333-444488888888";
let 反代IP = 'sjc.o00o.ooo' // 支持path传递 path=/?ed=2560&ip=host:port

export default {
  async fetch(访问请求) {
    const url = new URL(访问请求.url);
    反代IP = url.searchParams.get('ip') || 反代IP;

    if (访问请求.headers.get('Upgrade') === 'websocket'){
      // ⭐ 改造：统一走升级函数（内部自动兼容“首包/协议头”两种模式）
      return await 升级WS请求(访问请求);
    } else {
      return new Response(null, { status: 400 })
    }
  }
};

////////////////////////////////////////////////////////////////////////脚本主要架构//////////////////////////////////////////////////////////////////////

// 第一步：读取和构建基础访问结构
async function 升级WS请求(访问请求) {
  const 创建WS接口 = new WebSocketPair();
  const [客户端, WS接口] = Object.values(创建WS接口);

  // 读取访问标头中的WS通信数据（脚本1原逻辑）
  const 协议头 = 访问请求.headers.get('sec-websocket-protocol');

  if (协议头 && 协议头.length > 0) {
    // 仍按脚本1的方式：从协议头取 VL 数据并建链
    const 解密数据 = 使用64位加解密(协议头);      // 解密目标访问数据
    // 这里不需要先 accept；在建立传输管道时会 accept
    await 解析VL标头(解密数据, WS接口);           // 解析VL数据并进行TCP握手
    return new Response(null, { status: 101, webSocket: 客户端 });
  }

  // ⭐ 新增：没有协议头 => 兼容 sing-box：等待“首包”再解析
  WS接口.accept(); // 先接受，再监听首帧
  let 已处理首包 = false;

  WS接口.addEventListener('message', async (event) => {
    if (已处理首包) return;
    已处理首包 = true;

    try {
      // event.data 预期为 ArrayBuffer / Uint8Array（sing-box 会直接发 VL 首包）
      const 首包 = event.data instanceof ArrayBuffer
        ? event.data
        : (event.data?.buffer ?? event.data);

      // 直接复用脚本1的 解析VL标头：它会校验 UUID、解析地址端口、拨号并调用 建立传输管道
      await 解析VL标头(首包, WS接口);
    } catch (e) {
      try { WS接口.close(1011, '首包解析失败'); } catch {}
    }
  });

  // 若连接被立刻升级，我们先返回 101；后续由事件回调继续处理
  return new Response(null, { status: 101, webSocket: 客户端 });
}

function 使用64位加解密(还原混淆字符) {
  还原混淆字符 = 还原混淆字符.replace(/-/g, '+').replace(/_/g, '/');
  const 解密数据 = atob(还原混淆字符);
  const 解密_你_个_丁咚_咙_咚呛 = Uint8Array.from(解密数据, (c) => c.charCodeAt(0));
  return 解密_你_个_丁咚_咙_咚呛.buffer;
}

// 第二步：解读VL协议数据，创建TCP握手（复用脚本1原函数）
let 访问地址, 访问端口;
async function 解析VL标头(VL数据, WS接口, TCP接口) {
  if (验证VL的密钥(new Uint8Array(VL数据.slice(1, 17))) !== 哎呀呀这是我的VL密钥) {
    // ⭐ 小改：如在“首包模式”里校验失败，直接关闭 WS
    try { WS接口?.close?.(1008, '连接验证失败'); } catch {}
    return new Response('连接验证失败', { status: 400 });
  }
  const 获取数据定位 = new Uint8Array(VL数据)[17];
  const 提取端口索引 = 18 + 获取数据定位 + 1;
  const 建立端口缓存 = VL数据.slice(提取端口索引, 提取端口索引 + 2);
  访问端口 = new DataView(建立端口缓存).getUint16(0);
  const 提取地址索引 = 提取端口索引 + 2;
  const 建立地址缓存 = new Uint8Array(VL数据.slice(提取地址索引, 提取地址索引 + 1));
  const 识别地址类型 = 建立地址缓存[0];
  let 地址长度 = 0;
  let 地址信息索引 = 提取地址索引 + 1;
  switch (识别地址类型) {
    case 1:
      地址长度 = 4;
      访问地址 = new Uint8Array( VL数据.slice(地址信息索引, 地址信息索引 + 地址长度) ).join('.');
      break;
    case 2:
      地址长度 = new Uint8Array( VL数据.slice(地址信息索引, 地址信息索引 + 1) )[0];
      地址信息索引 += 1;
      访问地址 = new TextDecoder().decode( VL数据.slice(地址信息索引, 地址信息索引 + 地址长度) );
      break;
    case 3:
      地址长度 = 16;
      const dataView = new DataView( VL数据.slice(地址信息索引, 地址信息索引 + 地址长度) );
      const ipv6 = [];
      for (let i = 0; i < 8; i++) { ipv6.push(dataView.getUint16(i * 2).toString(16)); }
      访问地址 = ipv6.join(':');
      break;
    default:
      try { WS接口?.close?.(1008, '无效的访问地址'); } catch {}
      return new Response('无效的访问地址', { status: 400 });
  }
  const 写入初始数据 = VL数据.slice(地址信息索引 + 地址长度);

  try {
    TCP接口 = connect({ hostname: 访问地址, port: 访问端口 });
    await TCP接口.opened;
  } catch {
    // 脚本1原有的反代回退
    let [反代IP地址, 反代IP端口] = 反代IP.split(':');
    TCP接口 = connect({ hostname: 反代IP地址, port: 反代IP端口 || 访问端口 });
  }
  await TCP接口.opened;

  // 建立WS<->TCP通道（里边会 accept；在首包模式下上面已 accept，不影响）
  建立传输管道(WS接口, TCP接口, 写入初始数据);
}

function 验证VL的密钥(字节数组, 起始位置 = 0) {
  const 十六进制表 = Array.from({ length: 256 }, (_, 值) =>
    (值 + 256).toString(16).slice(1)
  );
  const 分段结构 = [4, 2, 2, 2, 6];
  let 当前索引 = 起始位置;
  const 格式化UUID = 分段结构
    .map(段长度 =>
      Array.from({ length: 段长度 }, () => 十六进制表[字节数组[当前索引++]]).join('')
    )
    .join('-')
    .toLowerCase();
  return 格式化UUID;
}

// 第三步：创建客户端WS-CF-目标的传输通道并监听状态（原逻辑不变）
async function 建立传输管道(WS接口, TCP接口, 写入初始数据, 写入队列 = Promise.resolve(), 回写队列 = Promise.resolve()) {
  let 累计接收字节数 = 0;
  let 已清理资源 = false;

  // 如果未被 accept，这里统一 accept；已 accept 则忽略
  try { WS接口.accept?.(); } catch {}

  // 按 VL 协议回写握手 OK
  try { WS接口.send(new Uint8Array([0, 0])); } catch {}

  const 传输数据 = TCP接口.writable.getWriter();
  const 读取数据 = TCP接口.readable.getReader();

  if (写入初始数据) {
    写入队列 = 写入队列.then(() => 传输数据.write(写入初始数据)).catch();
  }

  WS接口.addEventListener('message', event => {
    写入队列 = 写入队列.then(() => 传输数据.write(event.data)).catch();
  });

  启动回传();

  async function 启动回传() {
    let 字节计数 = 0;
    try {
      while (!已清理资源) {
        const { done: 流结束, value: 返回数据 } = await 读取数据.read();
        if (流结束) {
          await 清理资源();
          break;
        }
        if (返回数据?.length > 0) {
          累计接收字节数 += 返回数据.length;
          回写队列 = 回写队列.then(() => WS接口.send(返回数据)).catch();
          if ((累计接收字节数 - 字节计数) > 4 * 1024 * 1024) {
            await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 400));
            字节计数 = 累计接收字节数;
          }
        }
      }
    } catch {
      await 清理资源();
    }
  }

  async function 清理资源() {
    if (已清理资源) return;
    已清理资源 = true;
    await new Promise(resolve => setTimeout(resolve, 1000));
    try {
      WS接口.close(1000);
      await TCP接口.close?.();
    } catch {};
  }
}