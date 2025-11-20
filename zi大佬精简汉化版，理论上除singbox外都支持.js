import { connect } from 'cloudflare:sockets';

// ======================== 基础配置 ========================
let 用户ID = "88888888-1111-2222-3333-444488888888"; // 默认 UUID
let 代理IP = "";
// =========================================================

export default {
  async fetch(请求) {
    const url = new URL(请求.url);
    代理IP = url.searchParams.get('ip') || 代理IP;

    if (请求.headers.get('Upgrade') !== 'websocket')
      return new Response('Worker 正常运行中 (仅支持 WebSocket 请求)', { status: 200 });

    return await 处理VLESS请求(请求);
  }
};

// =========================================================
// 主逻辑：处理 VLESS over WebSocket
// =========================================================
async function 处理VLESS请求(请求) {
  const 对 = new WebSocketPair();
  const [客户端, 服务端] = Object.values(对);
  服务端.accept();

  const 早期数据头 = 请求.headers.get('sec-websocket-protocol') || '';
  const 可读流 = 创建可读WebSocket流(服务端, 早期数据头);
  const 远程连接 = { 值: null };
  let 写入UDP = null, 是否DNS = false;

  可读流.pipeTo(new WritableStream({
    async write(数据块) {
      // UDP DNS 模式
      if (是否DNS && 写入UDP) return 写入UDP(数据块);

      // 已建立 TCP 连接
      if (远程连接.值) {
        const 写入器 = 远程连接.值.writable.getWriter();
        await 写入器.write(数据块);
        写入器.releaseLock();
        return;
      }

      // 解析 VLESS 头
      const r = 解析VLESS头(数据块, 用户ID);
      if (r.出错) throw new Error(r.消息);

      const 响应头 = new Uint8Array([r.版本[0], 0]);
      const 客户端数据 = 数据块.slice(r.数据起始位置);

      // 处理 UDP DNS
      if (r.UDP) {
        if (r.端口 !== 53) throw new Error('UDP 仅支持 DNS (53端口)');
        const { 写入 } = await 处理UDP请求(服务端, 响应头);
        写入UDP = 写入; 是否DNS = true;
        写入UDP(new Uint8Array(客户端数据));
        return;
      }

      // 处理 TCP 代理
      处理TCP请求(远程连接, r.地址, r.端口, 客户端数据, 服务端, 响应头);
    }
  })).catch(() => 安全关闭(服务端));

  return new Response(null, { status: 101, webSocket: 客户端 });
}

// =========================================================
// TCP 处理逻辑
// =========================================================
async function 处理TCP请求(远程连接, 主机, 端口, 首包数据, WS, 响应头) {
  async function 建立连接并发送(IP, Port) {
    const Socket = connect({ hostname: IP, port: Port });
    远程连接.值 = Socket;
    const 写入器 = Socket.writable.getWriter();
    await 写入器.write(首包数据);
    写入器.releaseLock();
    return Socket;
  }

  async function 重试连接() {
    if (!代理IP) return 安全关闭(WS);
    let [IP, Port] = 代理IP.split(':'); Port = parseInt(Port) || 端口;
    const Socket = await 建立连接并发送(IP, Port);
    传输到WebSocket(Socket, WS, 响应头);
  }

  try {
    const Socket = await 建立连接并发送(主机, 端口);
    传输到WebSocket(Socket, WS, 响应头, 重试连接);
  } catch {
    await 重试连接();
  }
}

// =========================================================
// TCP -> WebSocket 数据传输
// =========================================================
async function 传输到WebSocket(Socket, WS, 响应头, 重试) {
  let 有数据 = false, 首次头 = 响应头;

  await Socket.readable.pipeTo(new WritableStream({
    async write(数据) {
      有数据 = true;
      WS.send(首次头 ? await new Blob([首次头, 数据]).arrayBuffer() : 数据);
      首次头 = null;
    }
  })).catch(() => 安全关闭(WS));

  if (!有数据 && 重试) 重试();
}

// =========================================================
// 将 WebSocket 转换为可读流
// =========================================================
function 创建可读WebSocket流(WS, 早期数据头) {
  let 已取消 = false;
  return new ReadableStream({
    start(控制器) {
      WS.addEventListener('message', e => !已取消 && 控制器.enqueue(e.data));
      WS.addEventListener('close', () => { 安全关闭(WS); if (!已取消) 控制器.close(); });
      const { 早期数据 } = Base64转数组(早期数据头);
      if (早期数据) 控制器.enqueue(早期数据);
    },
    cancel() { 已取消 = true; 安全关闭(WS); }
  });
}

// =========================================================
// 解析 VLESS 头部
// =========================================================
function 解析VLESS头(缓冲区, 用户ID) {
  if (缓冲区.byteLength < 24) return { 出错: true, 消息: '数据过短' };
  const 版本 = new Uint8Array(缓冲区.slice(0, 1));
  const UUID = 转为UUID(new Uint8Array(缓冲区.slice(1, 17)));
  if (UUID !== 用户ID) return { 出错: true, 消息: 'UUID 不匹配' };

  const 选项长度 = new Uint8Array(缓冲区.slice(17, 18))[0];
  const 命令 = new Uint8Array(缓冲区.slice(18 + 选项长度, 19 + 选项长度))[0];
  const UDP = 命令 === 2;
  const 端口 = new DataView(缓冲区.slice(19 + 选项长度, 21 + 选项长度)).getUint16(0);
  const 类型 = new Uint8Array(缓冲区.slice(21 + 选项长度, 22 + 选项长度))[0];
  let 索引 = 22 + 选项长度, 长度 = 0, 地址 = "";

  switch (类型) {
    case 1: 长度 = 4; 地址 = new Uint8Array(缓冲区.slice(索引, 索引 + 长度)).join('.'); break;
    case 2: 长度 = new Uint8Array(缓冲区.slice(索引, 索引 + 1))[0]; 索引++; 地址 = new TextDecoder().decode(缓冲区.slice(索引, 索引 + 长度)); break;
    case 3:
      长度 = 16; const dv = new DataView(缓冲区.slice(索引, 索引 + 长度));
      地址 = Array.from({ length: 8 }, (_, i) => dv.getUint16(i * 2).toString(16)).join(':');
      break;
  }

  return { 出错: false, 版本, 地址, 端口, UDP, 数据起始位置: 索引 + 长度 };
}

// =========================================================
// 处理 UDP DNS (通过 DoH 模拟实现)
// =========================================================
async function 处理UDP请求(WS, 响应头) {
  let 已发送头 = false;
  const 转换流 = new TransformStream({
    transform(块, 控制器) {
      for (let i = 0; i < 块.byteLength;) {
        const 长度 = new DataView(块.slice(i, i + 2)).getUint16(0);
        const 数据 = 块.slice(i + 2, i + 2 + 长度);
        i += 2 + 长度; 控制器.enqueue(数据);
      }
    }
  });

  转换流.readable.pipeTo(new WritableStream({
    async write(数据) {
      const 响应 = await fetch('https://1.1.1.1/dns-query', {
        method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: 数据
      });
      const 结果 = await 响应.arrayBuffer();
      const 长度 = 结果.byteLength;
      const 大小头 = new Uint8Array([(长度 >> 8) & 0xff, 长度 & 0xff]);
      WS.send(await new Blob([已发送头 ? 大小头 : [响应头, 大小头], 结果].flat()).arrayBuffer());
      已发送头 = true;
    }
  }));

  const 写入器 = 转换流.writable.getWriter();
  return { 写入: 数据 => 写入器.write(数据) };
}

// =========================================================
// 工具函数
// =========================================================
function Base64转数组(base64) {
  if (!base64) return {};
  base64 = base64.replace(/-/g, '+').replace(/_/g, '/');
  const 字符串 = atob(base64);
  return { 早期数据: Uint8Array.from(字符串, c => c.charCodeAt(0)).buffer };
}

function 安全关闭(ws) { try { ws.close(); } catch {} }

function 转为UUID(字节数组) {
  const hex = Array.from(字节数组, x => (x + 256).toString(16).slice(1));
  return `${hex.slice(0,4).join('')}-${hex.slice(4,6).join('')}-${hex.slice(6,8).join('')}-${hex.slice(8,10).join('')}-${hex.slice(10,16).join('')}`.toLowerCase();
}