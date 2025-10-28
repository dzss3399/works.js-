import { connect } from 'cloudflare:sockets';
//说明：抛弃了ed配置，不要设置/?ed=2560，自适应ws和xhttp双传输协议，xhttp传输模式选stream-one，不适合pages部署，只用ws建议pages部署，互不影响
const Snippets部署 = false; //如果是Snippets部署【xhttp新传输模式稳定性有提升，可稳定流媒体】，需要设置为true，否则false，使用Snippets部署将会自动禁用【nat64、DOH查询转换、数据库】等功能

let 哎呀呀这是我的VL密钥 = "ae11a11c-cbcc-4dd6-bc51-5c61cc0a62a8"; //建议更改为自己的标准化UUID

let 启用反代功能 = true //选择是否启用反代功能【总开关】，false，true，现在你可以自由的选择是否启用反代功能了
let 反代IP = '' //反代IP或域名，反代IP端口一般情况下不用填写，如果你非要用非标反代的话，可以填'ts.hpc.tw:443'这样

let 启用NAT64反代 = false //NAT64如果启用，优先级高于S5反代和原始反代，NAT64只支持ipv4，启用则需禁用doh查询ipv6功能，Snippets部署则此功能失效
let 启用NAT64全局反代 = false //选择是否启用全局NAT64功能，原理带宽与S5类似，受限于NAT64的速度
let 我的NAT64地址 = '[2602:fc59:b0:64::]' //NAT64地址，支持带端口，示例[2602:fc59:b0:64::]:443

let 启用SOCKS5反代 = false //如果启用此功能，原始反代将失效，很多S5不一定支持ipv6，启用则需禁用doh查询ipv6功能
let 启用SOCKS5全局反代 = false //选择是否启用SOCKS5全局反代，启用后所有访问都是S5的落地【无论你客户端选什么节点】，访问路径是客户端--CF--SOCKS5，当然启用此功能后延迟=CF+SOCKS5，带宽取决于SOCKS5的带宽，不再享受CF高速和随时满带宽的待遇
let 我的SOCKS5账号 = [
  '@Enkelte_notif:@Notif_Chat@115.91.26.114:2470',
] //格式'账号:密码@地址:端口'，示例admin:admin@127.0.0.1:443或admin:admin@[IPV6]:443，支持无账号密码示例@127.0.0.1:443

let 启用新版传输模式 = true //开启则使用天书独有的队列传输方式，关闭则是原始管道流传输方式【如果你是付费用户，追求带宽，用管道流，如果你是免费用户，追求稳定丝滑，用队列传输，XHTTP无所谓了，包断的，不想断花钱去:p】
//////////////////////////////////////////////////////////////////////////DOH配置/////////////////////////////////////////////////////////////////////////
let 启用DOH查询转换 = false //关闭则是原始模式，若使用NAT64则必须开启此功能，Snippets部署则此功能失效
let 优先查询IPV6 = true //启用则优先查询并使用IPV6连接，大多反代可能不支持IPV6，建议关闭此功能，若使用NAT64则必须关闭此功能
let 严格TTL缓存 = true //新增了脚本本地缓存，可以维持几分钟甚至几小时左右，如果启用则严格按照TTL时间进行缓存，关闭可减少频繁查询的次数，提升速度，个人视使用环境选择
let DOH服务器列表 = [ //DOH地址，基本上已经涵盖市面上所有通用地址了，一般无需修改
  // 国际通用
  "https://1.1.1.1/dns-query",                // Cloudflare IP
  //"https://cloudflare-dns.com/dns-query",     // Cloudflare 主域名
  //"https://dns.google/resolve",               // Google 公共 DNS
  //"https://dns.adguard.com/resolve",          // AdGuard 去广告 DNS

  // 国际新增推荐
  //"https://dns.nextdns.io/resolve",           // NextDNS

  // 国内兼容
  //"https://dns.alidns.com/resolve",           // 阿里公共 DNS（223.5.5.5）
  //"https://doh.pub/dns-query",                // 腾讯公共 DNS（119.29.29.29）
];
//////////////////////////////////////////////////////////////////////////数据库配置///////////////////////////////////////////////////////////////////////
let 启用数据库 = false //会用数据库的可以启用，否则保持关闭别用就好，数据库速度并没有很快，只是一个长期缓存的玩法策略，基本上现在可以弃用的，绑定变量名DB，Snippets部署则此功能失效
let 数据库缓存策略 = 1 //数据库缓存策略，1代表使用TTL缓存【效果好，更新频率高】，2代表固定缓存时间4小时一次【可以减少频繁更新，已经可以适应大部分网站】
//////////////////////////////////////////////////////////////////////////主要架构////////////////////////////////////////////////////////////////////////
export default {
  async fetch(访问请求, env) {
    const 读取路径 = decodeURIComponent(访问请求.url.replace(/^https?:\/\/[^/]+/, ''));
    const 取参数 = (key) => 读取路径.match(new RegExp(`(?:^|[/?&])${key}=([^&/]+)`))?.[1];
    const 解析布尔 = (值, 默认) => ({ true: true, false: false }[值] ?? 默认);
    启用新版传输模式 = 解析布尔(取参数('tsmod-open'), 启用新版传输模式);
    优先查询IPV6 = 解析布尔(取参数('doh-ipv6'), 优先查询IPV6);
    启用数据库 = 解析布尔(取参数('db-open'), 启用数据库);
    反代IP = 取参数('proxyip') || 反代IP;
    我的NAT64地址 = 取参数('nat64') || 我的NAT64地址;
    启用NAT64反代 = 解析布尔(取参数('nat64-open'), 启用NAT64反代);
    启用NAT64全局反代 = 解析布尔(取参数('nat64-global'), 启用NAT64全局反代);
    const SOCKS5新账号 = 取参数('socks5');
    我的SOCKS5账号 = [...(SOCKS5新账号 ? [SOCKS5新账号] : []), ...我的SOCKS5账号];
    启用SOCKS5反代 = 解析布尔(取参数('socks5-open'), 启用SOCKS5反代);
    启用SOCKS5全局反代 = 解析布尔(取参数('socks5-global'), 启用SOCKS5全局反代);
    if (!Snippets部署) 数据库 = env.DB;
    if (访问请求.headers.get('Upgrade') === 'websocket'){
      const [客户端, WS接口] = Object.values(new WebSocketPair());
      WS接口.accept();
      处理数据(WS接口, true);
      return new Response(null, { status: 101, webSocket: 客户端 }); //一切准备就绪后，回复客户端WS连接升级成功
    } else if (访问请求.method === 'POST' && 访问请求.body) {
      return await 处理数据(访问请求, false);
    } else {
      return new Response('Hello World!', { status: 200 });
    }
  }
};
async function 处理数据(数据接口, 传输协议, 传输队列 = Promise.resolve()) {
  if (传输协议) {
    处理WS流(数据接口);
  } else {
    return await 处理XHTTP流(数据接口);
  }
  async function 处理WS流(WS接口, 是首包 = true, 处理首包数据 = Promise.resolve(), 传输数据) {
    WS接口.addEventListener('message', async event => {
      if (是首包) {
        是首包 = false;
        处理首包数据 = 处理首包数据.then(async () => await 处理首包(event.data)).catch(e => {throw (e)});
      } else {
        await 处理首包数据;
        if (启用新版传输模式) {
          传输队列 = 传输队列.then(async () => {try { await 传输数据.write(event.data) } catch {}}).catch(e => {throw (e)});
        } else {
          await 传输数据.write(event.data);
        }
      }
    });
    async function 处理首包 (首包数据) {
      const 解析首包 = await 解析首包数据(new Uint8Array(首包数据));
      传输数据 = 解析首包.TCP接口.writable.getWriter();
      if (解析首包.是DNS) {
        WS接口.send(解析首包.初始数据);
        return;
      }
      await 传输数据.write(解析首包.初始数据);
      数据回传通道(解析首包.TCP接口, 解析首包.版本号).pipeTo(new WritableStream({ write(数据) { WS接口.send(数据) } }));
    }
  }
  async function 处理XHTTP流(访问请求) {
    try {
      const 读取器 = 访问请求.body.getReader();
      const 请求数据 = (await 读取器.read()).value;
      const 解析首包 = await 解析首包数据(new Uint8Array(请求数据));
      if (解析首包.是DNS) return new Response(解析首包.初始数据);
      const 传输数据 = 解析首包.TCP接口.writable.getWriter();
      await 传输数据.write(解析首包.初始数据);
      if (启用新版传输模式) {
        数据发送通道(读取器, 传输数据);
      } else {
        读取器.releaseLock();
        传输数据.releaseLock();
        访问请求.body.pipeTo(解析首包.TCP接口.writable);
      }
      return new Response(数据回传通道(解析首包.TCP接口, 解析首包.版本号));
    } catch (e) {
      return new Response(`拒绝访问：${e}`, { status: 400 });
    }
  }
  async function 数据发送通道(读取器, 传输数据) {
    while (true) {
      const { done: 流结束, value: 请求数据 } = await 读取器.read();
      if (流结束) break;
      if(请求数据?.length > 0) 传输队列 = 传输队列.then(async () => {try { await 传输数据.write(请求数据) } catch {}}).catch(e => {throw (e)});
    }
  }
  function 数据回传通道 (TCP接口, 版本号) {
    const 读取管道 = new TransformStream({
      async start(控制器) { 
        控制器.enqueue(new Uint8Array([版本号, 0]));
        if (启用新版传输模式) {
          let 回写计数 = 0;
          const TCP缓存 = [];
          const 读取数据 = TCP接口.readable.getReader();
          while (true) {
            const { done: 流结束, value: 返回数据 } = await 读取数据.read();
            if (返回数据?.length > 0) {
              if (返回数据.length >= 4096) {
                TCP缓存.push(返回数据);
                while (true) {
                  const 返回数据 = (await 读取数据.read()).value;
                  TCP缓存.push(返回数据);
                  if (返回数据.length < 4096 || TCP缓存.length > 200) {
                    if (++回写计数 > 2 && TCP缓存.length > 100) await new Promise(resolve => setTimeout(resolve, 回写计数 * (10 + Math.random() * 40)));
                    while (TCP缓存.length > 0) {
                      const 数据块 = TCP缓存.shift();
                      传输队列 = 传输队列.then(() => 控制器.enqueue(数据块)).catch(e => {throw (e)});
                    }
                    if (回写计数 > 10) 回写计数 = 0;
                    break;
                  }
                }
              } else {
                传输队列 = 传输队列.then(() => 控制器.enqueue(返回数据)).catch(e => {throw (e)});
              }
            }
            if (流结束) break;
          }
        }
      },
      transform(返回数据, 控制器) { 控制器.enqueue(返回数据) }
    });
    if (!启用新版传输模式) TCP接口.readable.pipeTo(读取管道.writable);
    return 读取管道.readable;
  }
}
async function 解析首包数据(二进制数据) {
  let 识别地址类型, 访问地址, 地址长度;
  if (二进制数据.length < 32) throw new Error('数据长度不足');
  const 获取协议头 = 二进制数据[0];
  const 验证VL的密钥 = (a, i = 0) => [...a.slice(i, i + 16)].map(b => b.toString(16).padStart(2, '0')).join('').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
  if (验证VL的密钥(二进制数据.slice(1, 17)) !== 哎呀呀这是我的VL密钥) throw new Error('UUID验证失败');
  const 提取端口索引 = 18 + 二进制数据[17] + 1;
  const 访问端口 = new DataView(二进制数据.buffer, 提取端口索引, 2).getUint16(0);
  if (访问端口 === 53 && 启用DOH查询转换 && !Snippets部署) { //这个处理是应对某些客户端优先强制查询dns的情况，通过加密通道udp over tcp的
    const 提取DNS查询报文 = 二进制数据.slice(提取端口索引 + 9);
    const 查询DOH结果 = await fetch('https://1.1.1.1/dns-query', {
      method: 'POST',
      headers: {
        'content-type': 'application/dns-message',
      },
      body: 提取DNS查询报文
    })
    const 提取DOH结果 = await 查询DOH结果.arrayBuffer();
    const 构建长度头部 = new Uint8Array([(提取DOH结果.byteLength >> 8) & 0xff, 提取DOH结果.byteLength & 0xff]);
    const 拼接DNS结果 = await new Blob([构建长度头部, 提取DOH结果]);
    return { 初始数据: 拼接DNS结果, 是DNS: true }
  }
  const 提取地址索引 = 提取端口索引 + 2;
  识别地址类型 = 二进制数据[提取地址索引];
  let 地址信息索引 = 提取地址索引 + 1;
  switch (识别地址类型) {
    case 1:
      地址长度 = 4;
      访问地址 = 二进制数据.slice(地址信息索引, 地址信息索引 + 地址长度).join('.');
      break;
    case 2:
      地址长度 = 二进制数据[地址信息索引];
      地址信息索引 += 1;
      const 访问域名 = new TextDecoder().decode(二进制数据.slice(地址信息索引, 地址信息索引 + 地址长度));
      if (启用DOH查询转换 && !Snippets部署) {
        访问地址 = await 查询最快IP(访问域名);
        const 匹配结果 = 匹配地址(访问地址);
        if (匹配结果.类型 === 'ipv6') 识别地址类型 = 3;
        if (匹配结果.类型 === 'ipv4') 识别地址类型 = 1;
      } else {
        访问地址 = 访问域名;
      }
      break;
    case 3:
      地址长度 = 16;
      const ipv6 = [];
      const 读取IPV6地址 = new DataView(二进制数据.buffer, 地址信息索引, 16);
      for (let i = 0; i < 8; i++) ipv6.push(读取IPV6地址.getUint16(i * 2).toString(16).padStart(4, '0')); //修复了v6地址完全展开，方便s5可直接调用
      访问地址 = ipv6.join(':');
      break;
    default:
      throw new Error ('无效的访问地址');
  }
  const 写入初始数据 = 二进制数据.slice(地址信息索引 + 地址长度);
  const TCP接口 = await 创建TCP接口连接(访问地址, 访问端口, 识别地址类型);
  return { 版本号: 获取协议头, TCP接口: TCP接口, 初始数据: 写入初始数据 };
}
async function 创建TCP接口连接(访问地址, 访问端口, 识别地址类型, TCP接口) {
  if (!Snippets部署 && 启用反代功能 && 启用NAT64反代 && 启用NAT64全局反代 && 识别地址类型 === 1) {
    const 解析NAT64地址 = 匹配地址(我的NAT64地址);
    const 拼接NAT64地址 = `[${解析NAT64地址.地址.split(':').slice(0,6).join(':')}:${访问地址.split('.').map(n => (+n).toString(16).padStart(2,'0')).join('').replace(/(.{4})/, '$1:')}]`;
    TCP接口 = connect({ hostname: 拼接NAT64地址, port: 解析NAT64地址.端口 });
  } else {
    if (启用反代功能 && 启用SOCKS5反代 && 启用SOCKS5全局反代) {
      TCP接口 = await 创建SOCKS5接口(识别地址类型, 访问地址, 访问端口);
    } else {
      try {
        const 解析IP = 匹配地址(访问地址);
        if (解析IP.类型 === 'ipv6') 解析IP.地址 = `[${解析IP.地址}]`
        TCP接口 = connect({ hostname: 解析IP.地址, port: 访问端口 });
        await TCP接口.opened;
      } catch {
        if (启用反代功能) {
          if (!Snippets部署 && 启用NAT64反代 && 识别地址类型 === 1) {
            const 解析NAT64地址 = 匹配地址(我的NAT64地址);
            const 拼接NAT64地址 = `[${解析NAT64地址.地址}${访问地址.split('.').map(n=>(+n).toString(16).padStart(2,'0')).join('').replace(/(.{4})/, '$1:')}]`;
            TCP接口 = connect({ hostname: 拼接NAT64地址, port: 解析NAT64地址.端口 });
          } else if (启用SOCKS5反代) {
            TCP接口 = await 创建SOCKS5接口(识别地址类型, 访问地址, 访问端口);
          } else {
            const 解析反代IP = 匹配地址(反代IP);
            if (解析反代IP.类型 === 'ipv6') 解析反代IP.地址 = `[${解析反代IP.地址}]`
            TCP接口 = connect({ hostname: 解析反代IP.地址, port: 解析反代IP.端口});
          }
        }
      }
    }
  }
  return TCP接口;
}
globalThis.DNS缓存记录 = globalThis.DNS缓存记录 ??= new Map();
let 数据库;
async function 查询最快IP(访问域名, 获取DOH结果 = null) {
  /* 手动建表的语句，复制以下字段到对应绑定的D1数据库的控制台中粘贴执行
  CREATE TABLE IF NOT EXISTS dns_cache (
    域名 TEXT PRIMARY KEY,
    IP TEXT,
    更新时间 TEXT,
    TTL INTEGER,
    TTL更新时间 INTEGER,
    TTL过期时间 INTEGER
  );
  */
  const 读取缓存时间 = DNS缓存记录.get('缓存保活');
  if (!读取缓存时间) DNS缓存记录.set('缓存保活', { 缓存时间: Date.now() });
  const 进程控制器 = [];
  const 开始查询时间 = Date.now();
  const 查询DNS缓存记录 = DNS缓存记录.get(访问域名);
  if (查询DNS缓存记录 && (!严格TTL缓存 || 开始查询时间 < 查询DNS缓存记录.TTL过期时间)) {
    console.log(`${访问域名}已有缓存: ${查询DNS缓存记录.IP}，总缓存已保活: ${格式化时间(Date.now() - 读取缓存时间.缓存时间)}，缓存条目：${DNS缓存记录.size - 1}`);
    return 查询DNS缓存记录.IP;
  }
  if (启用数据库 && 数据库) {
    const 查询数据库结果 = await Promise.race([
      数据库.prepare(
        "SELECT IP, 更新时间, TTL, TTL更新时间, TTL过期时间 FROM dns_cache WHERE 域名 = ?"
      ).bind(访问域名).first(),
      new Promise(resolve => setTimeout(() => resolve(null), 200))
    ]);
    if (查询数据库结果) {
      if (数据库缓存策略 === 1) {
        if (开始查询时间 < 查询数据库结果.TTL过期时间) {
          DNS缓存记录.set(访问域名, {...查询数据库结果, 缓存时间: Date.now()});
          console.log(`${访问域名}已有数据库: ${查询数据库结果.IP}，直接返回结果，查询时间: ${Date.now() - 开始查询时间} 毫秒`);
          return 查询数据库结果.IP;
        } else {
          console.log(`${访问域名}数据库: ${查询数据库结果.IP} 已过期：${格式化时间(开始查询时间 - 查询数据库结果.TTL过期时间)}，开始更新DOH`);
        }
      }
      if (数据库缓存策略 === 2) {
        if ((开始查询时间 - 查询数据库结果.TTL更新时间) < 4 * 60 * 60 * 1000) {
          DNS缓存记录.set(访问域名, {...查询数据库结果, 缓存时间: Date.now()});
          console.log(`${访问域名}已有数据库: ${查询数据库结果.IP}，直接返回结果，查询时间: ${Date.now() - 开始查询时间} 毫秒`);
          return 查询数据库结果.IP;
        } else {
          console.log(`${访问域名}数据库: ${查询数据库结果.IP} 已过期：${格式化时间(开始查询时间 - 查询数据库结果.TTL过期时间)}，开始更新DOH`);
        }
      }
    }
  }
  const 构造所有请求 = (type) => {
    const 请求列表 = [];
    const 构造DOH请求 = (type) => 
      DOH服务器列表.map(DOH => {
        const 取消控制器 = new AbortController();
        进程控制器.push(取消控制器);
        return fetch(`${DOH}?name=${访问域名}&type=${type}`, {
          method: 'GET',
          headers: { 'Accept': 'application/dns-json' },
          signal: 取消控制器.signal
        }).then(res => res.json())
          .then(json => {
            const 查询结果 = json.Answer?.filter(r => r.type === (type === 'A' ? 1 : 28)).pop();
            if (查询结果?.data) {
              return { IP: 查询结果.data, TTL: 查询结果.TTL ?? 120, DOH: DOH };
            }
            return Promise.reject(`无 ${type} 记录`);
          })
          .catch(err => Promise.reject(`${DOH} ${type} 请求失败: ${err}`));
      });
    请求列表.push(...构造DOH请求(type));
    return 请求列表;
  };
  try {
    if (优先查询IPV6) {
      try {
        获取DOH结果 = await Promise.any(构造所有请求('AAAA'));
        const 匹配结果 = 匹配地址(获取DOH结果.IP);
        if (匹配结果.类型 !== 'ipv6') throw new Error ('获取ipv6地址失败，尝试获取ipv4地址')
        return 匹配结果.地址;
      } catch {
        获取DOH结果 = await Promise.any(构造所有请求('A'));
      }
    } else {
      获取DOH结果 = await Promise.any(构造所有请求('A'));
    }
    const 匹配结果 = 匹配地址(获取DOH结果.IP);
    if (匹配结果.类型 !== 'ipv4') throw new Error ('获取IP地址失败')
    return 匹配结果.地址;
  } catch (e) {
    return 访问域名;
  } finally {
    try { 进程控制器.forEach(取消控制器 => 取消控制器.abort()) } catch {};
    const 匹配结果 = 匹配地址(获取DOH结果.IP);
    if (匹配结果.类型 !== '域名' && 获取DOH结果.TTL) {
      console.log(`${访问域名}查询结果: ${匹配结果.地址}，由: ${获取DOH结果.DOH} 查询所得，查询时间: ${Date.now() - 开始查询时间} 毫秒`);
      const 更新时间 = new Date(开始查询时间 + 8 * 60 * 60 * 1000).toISOString();
      const TTL过期时间 = 开始查询时间 + 获取DOH结果.TTL * 1000;
      DNS缓存记录.set(访问域名, {
        域名: 访问域名,
        IP: 匹配结果.地址,
        更新时间: 更新时间,
        TTL: 获取DOH结果.TTL,
        TTL更新时间: 开始查询时间,
        TTL过期时间: TTL过期时间,
        缓存时间: Date.now()
      });
      if (启用数据库 && 数据库) {
        await 数据库.prepare(`
          INSERT INTO dns_cache (域名, IP, 更新时间, TTL, TTL更新时间, TTL过期时间)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(域名) DO UPDATE SET
            IP = excluded.IP,
            更新时间 = excluded.更新时间,
            TTL = excluded.TTL,
            TTL更新时间 = excluded.TTL更新时间,
            TTL过期时间 = excluded.TTL过期时间
          WHERE excluded.更新时间 > dns_cache.更新时间
        `).bind(
          访问域名,
          匹配结果.地址,
          更新时间,
          获取DOH结果.TTL,
          开始查询时间,
          TTL过期时间
        ).run();
      }
    }
  }
}
//////////////////////////////////////////////////////////////////////////SOCKS5部分//////////////////////////////////////////////////////////////////////
async function 创建SOCKS5接口(识别地址类型, 访问地址, 访问端口, 解析SOCKS5, SOCKS5接口, 转换访问地址, 传输数据, 读取数据) {
  let 索引SOCKS5账号 = 0;
  我的SOCKS5账号 = Array.isArray(我的SOCKS5账号) ? 我的SOCKS5账号 : [我的SOCKS5账号];
  while (索引SOCKS5账号 < 我的SOCKS5账号.length) {
    const 提取SOCKS5账号 = 我的SOCKS5账号[索引SOCKS5账号]
    try {
      解析SOCKS5 = await 获取SOCKS5账号(提取SOCKS5账号);
      SOCKS5接口 = connect({ hostname: 解析SOCKS5.地址, port: 解析SOCKS5.端口 });
      await SOCKS5接口.opened;
      传输数据 = SOCKS5接口.writable.getWriter();
      读取数据 = SOCKS5接口.readable.getReader();
      const 转换数组 = new TextEncoder(); //把文本内容转换为字节数组，如账号，密码，域名，方便与S5建立连接
      const 构建S5认证 = new Uint8Array([5, 2, 0, 2]); //构建认证信息,支持无认证和用户名/密码认证
      await 传输数据.write(构建S5认证); //发送认证信息，确认目标是否需要用户名密码认证
      const 读取认证要求 = (await 读取数据.read()).value;
      if (读取认证要求[1] === 0x02) { //检查是否需要用户名/密码认证
        if (!解析SOCKS5.账号 || !解析SOCKS5.密码) {
          throw new Error (`未配置账号密码`);
        }
        const 构建账号密码包 = new Uint8Array([ 1, 解析SOCKS5.账号.length, ...转换数组.encode(解析SOCKS5.账号), 解析SOCKS5.密码.length, ...转换数组.encode(解析SOCKS5.密码) ]); //构建账号密码数据包，把字符转换为字节数组
        await 传输数据.write(构建账号密码包); //发送账号密码认证信息
        const 读取账号密码认证结果 = (await 读取数据.read()).value;
        if (读取账号密码认证结果[0] !== 0x01 || 读取账号密码认证结果[1] !== 0x00) { //检查账号密码认证结果，认证失败则退出
          throw new Error (`账号密码错误`);
        }
      }
      switch (识别地址类型) {
        case 1: // IPv4
          转换访问地址 = new Uint8Array( [1, ...访问地址.split('.').map(Number)] );
          break;
        case 2: // 域名
          转换访问地址 = new Uint8Array( [3, 访问地址.length, ...转换数组.encode(访问地址)] );
          break;
        case 3: // IPv6
          转换访问地址 = new Uint8Array( [4, ...访问地址.split(':').flatMap(s => [(parseInt(s, 16) >> 8) & 255, parseInt(s, 16) & 255])] );
          break;
      }
      const 构建转换后的访问地址 = new Uint8Array([ 5, 1, 0, ...转换访问地址, 访问端口 >> 8, 访问端口 & 0xff ]); //构建转换好的地址消息
      await 传输数据.write(构建转换后的访问地址); //发送转换后的地址
      const 检查返回响应 = (await 读取数据.read()).value;
      if (检查返回响应[0] !== 0x05 || 检查返回响应[1] !== 0x00) {
        throw new Error (`目标地址连接失败，访问地址: ${访问地址}，地址类型: ${识别地址类型}`);
      }
      传输数据.releaseLock();
      读取数据.releaseLock();
      return SOCKS5接口;
    } catch {
      索引SOCKS5账号++
    };
  }
  传输数据?.releaseLock();
  读取数据?.releaseLock();
  await SOCKS5接口?.close();
  throw new Error (`所有SOCKS5账号失效`);
}
async function 获取SOCKS5账号(SOCKS5) {
  const 分隔账号 = SOCKS5.includes("@") ? SOCKS5.lastIndexOf("@") : -1;
  const 账号段 = SOCKS5.slice(0, 分隔账号);
  const 地址段 = 分隔账号 !== -1 ? SOCKS5.slice(分隔账号 + 1) : SOCKS5;
  const [账号, 密码] = [账号段.slice(0, 账号段.lastIndexOf(":")), 账号段.slice(账号段.lastIndexOf(":") + 1)];
  const 解析SOCKS5地址 = 匹配地址(地址段);
  if (解析SOCKS5地址.类型 === 'ipv6') 解析SOCKS5地址.地址 = `[${解析SOCKS5地址.地址}]`
  return { 账号: 账号, 密码: 密码, 地址: 解析SOCKS5地址.地址 , 端口: 解析SOCKS5地址.端口 };
}
function 匹配地址(地址) {
  const 匹配 = 地址.match(/^(?:\[(?<ipv6>(?!fc00:)(?!fd00:)(?!fe80:)(?!::1)(?!0:)[0-9a-fA-F:]+)\]|(?<ipv6>(?!fc00:)(?!fd00:)(?!fe80:)(?!::1)(?!0:)[0-9a-fA-F:]+)|(?<ipv4>(?!10\.)(?!127\.)(?!169\.254\.)(?!172\.(1[6-9]|2\d|3[0-1])\.)(?!192\.168\.)(?!0\.)\d{1,3}(?:\.\d{1,3}){3})|(?<domain>[a-zA-Z0-9.-]+))(?::(?<port>\d+))?$/);  
  const { ipv6, ipv4, domain, port } = 匹配.groups;
  function 展开IPv6(ip) {
    ip = ip.replace(/^\[|\]$/g, '');
    if (ip.includes('::')) {
      const [前, 后] = ip.split('::');
      const 前段 = 前 ? 前.split(':') : [];
      const 后段 = 后 ? 后.split(':') : [];
      const 缺失数量 = 8 - (前段.length + 后段.length);
      const 填充 = Array(缺失数量).fill('0');
      ip = [...前段, ...填充, ...后段].join(':');
    }
    return ip
      .split(':')
      .map(x => x.padStart(4, '0').toLowerCase())
      .join(':');
  }
  const 展开IPv6地址 = ipv6 ? 展开IPv6(ipv6) : null;
  return {
    类型: ipv6 ? 'ipv6' : ipv4 ? 'ipv4' : '域名',
    地址: 展开IPv6地址 || ipv4 || domain,
    端口: port ? Number(port) : 443
  };
}
function 格式化时间(毫秒数) {
  const 总毫秒 = 毫秒数;
  const 小时 = Math.floor(总毫秒 / (3600 * 1000));
  const 分钟 = Math.floor((总毫秒 % (3600 * 1000)) / (60 * 1000));
  const 秒 = Math.floor((总毫秒 % (60 * 1000)) / 1000);
  const 毫秒 = 总毫秒 % 1000;
  return `${小时.toString().padStart(2, '0')}:${分钟.toString().padStart(2, '0')}:${秒.toString().padStart(2, '0')}.${毫秒.toString().padStart(3, '0')}`;
}
function 转换为十六进制(数据) {
  const 字节数组 = 数据 instanceof ArrayBuffer ? new Uint8Array(数据) : 数据;
  return Array.from(字节数组)
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join(" ");
}