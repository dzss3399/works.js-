const FIXED_UUID = ''; // 用于VLESS协议

const FIXED_TROJAN_PASSWORD = ''; // 用于Trojan协议

import { connect } from "cloudflare:sockets";

let 代理IP = '';

let 启用SOCKS5代理 = null;

let 启用SOCKS5全局代理 = false;

let 我的SOCKS5账号 = '';

//////////////////////////////////////////////////////////////////////////地区自适应ProxyIP配置////////////////////////////////////////////////////////////////////////

// 启用地区匹配功能
let enableRegionMatching = true;
let currentWorkerRegion = '';

// 地区映射配置
const regionMapping = {
    'US': ['🇺🇸 美国', 'US', 'United States'],
    'SG': ['🇸🇬 新加坡', 'SG', 'Singapore'],
    'JP': ['🇯🇵 日本', 'JP', 'Japan'],
    'HK': ['🇭🇰 香港', 'HK', 'Hong Kong'],
    'KR': ['🇰🇷 韩国', 'KR', 'South Korea'],
    'DE': ['🇩🇪 德国', 'DE', 'Germany'],
    'SE': ['🇸🇪 瑞典', 'SE', 'Sweden'],
    'NL': ['🇳🇱 荷兰', 'NL', 'Netherlands'],
    'FI': ['🇫🇮 芬兰', 'FI', 'Finland'],
    'GB': ['🇬🇧 英国', 'GB', 'United Kingdom'],
    'Oracle': ['甲骨文', 'Oracle'],
    'DigitalOcean': ['数码海', 'DigitalOcean'],
    'Vultr': ['Vultr', 'Vultr'],
    'Multacom': ['Multacom', 'Multacom']
};

// ProxyIP备用域名列表（按地区分类）
let backupIPs = [
    { domain: 'ProxyIP.US.CMLiussss.net', region: 'US', regionCode: 'US', port: 443 },
    { domain: 'ProxyIP.SG.CMLiussss.net', region: 'SG', regionCode: 'SG', port: 443 },
    { domain: 'ProxyIP.JP.CMLiussss.net', region: 'JP', regionCode: 'JP', port: 443 },
    { domain: 'ProxyIP.HK.CMLiussss.net', region: 'HK', regionCode: 'HK', port: 443 },
    { domain: 'ProxyIP.KR.CMLiussss.net', region: 'KR', regionCode: 'KR', port: 443 },
    { domain: 'ProxyIP.DE.CMLiussss.net', region: 'DE', regionCode: 'DE', port: 443 },
    { domain: 'ProxyIP.SE.CMLiussss.net', region: 'SE', regionCode: 'SE', port: 443 },
    { domain: 'ProxyIP.NL.CMLiussss.net', region: 'NL', regionCode: 'NL', port: 443 },
    { domain: 'ProxyIP.FI.CMLiussss.net', region: 'FI', regionCode: 'FI', port: 443 },
    { domain: 'ProxyIP.GB.CMLiussss.net', region: 'GB', regionCode: 'GB', port: 443 },
    { domain: 'ProxyIP.Oracle.cmliussss.net', region: 'Oracle', regionCode: 'Oracle', port: 443 },
    { domain: 'ProxyIP.DigitalOcean.CMLiussss.net', region: 'DigitalOcean', regionCode: 'DigitalOcean', port: 443 },
    { domain: 'ProxyIP.Vultr.CMLiussss.net', region: 'Vultr', regionCode: 'Vultr', port: 443 },
    { domain: 'ProxyIP.Multacom.CMLiussss.net', region: 'Multacom', regionCode: 'Multacom', port: 443 }
];

// 地区检测函数
async function detectWorkerRegion(request) {
    try {
        const cfCountry = request.cf?.country;

        if (cfCountry) {
            const countryToRegion = {
                'US': 'US', 'SG': 'SG', 'JP': 'JP', 'HK': 'HK', 'KR': 'KR',
                'DE': 'DE', 'SE': 'SE', 'NL': 'NL', 'FI': 'FI', 'GB': 'GB',
                'CN': 'HK', 'TW': 'HK', 'AU': 'SG', 'CA': 'US',
                'FR': 'DE', 'IT': 'DE', 'ES': 'DE', 'CH': 'DE',
                'AT': 'DE', 'BE': 'NL', 'DK': 'SE', 'NO': 'SE', 'IE': 'GB'
            };

            if (countryToRegion[cfCountry]) {
                return countryToRegion[cfCountry];
            }
        }

        return 'HK'; // 默认香港

    } catch (error) {
        return 'HK';
    }
}

// 获取邻近地区列表
function getNearbyRegions(region) {
    const nearbyMap = {
        'US': ['SG', 'JP', 'HK', 'KR'],
        'SG': ['JP', 'HK', 'KR', 'US'],
        'JP': ['SG', 'HK', 'KR', 'US'],
        'HK': ['SG', 'JP', 'KR', 'US'],
        'KR': ['JP', 'HK', 'SG', 'US'],
        'DE': ['NL', 'GB', 'SE', 'FI'],
        'SE': ['DE', 'NL', 'FI', 'GB'],
        'NL': ['DE', 'GB', 'SE', 'FI'],
        'FI': ['SE', 'DE', 'NL', 'GB'],
        'GB': ['DE', 'NL', 'SE', 'FI']
    };

    return nearbyMap[region] || [];
}

// 获取按优先级排序的所有地区
function getAllRegionsByPriority(region) {
    const nearbyRegions = getNearbyRegions(region);
    const allRegions = ['US', 'SG', 'JP', 'HK', 'KR', 'DE', 'SE', 'NL', 'FI', 'GB'];

    return [region, ...nearbyRegions, ...allRegions.filter(r => r !== region && !nearbyRegions.includes(r))];
}

// 智能地区选择
function getSmartRegionSelection(workerRegion, availableIPs) {
    if (!enableRegionMatching || !workerRegion) {
        return availableIPs;
    }

    const priorityRegions = getAllRegionsByPriority(workerRegion);
    const sortedIPs = [];

    for (const region of priorityRegions) {
        const regionIPs = availableIPs.filter(ip => ip.regionCode === region);
        sortedIPs.push(...regionIPs);
    }

    return sortedIPs;
}

// 获取最佳备用IP
async function getBestBackupIP(workerRegion = '') {
    if (backupIPs.length === 0) {
        return null;
    }

    const availableIPs = backupIPs.map(ip => ({ ...ip, available: true }));

    if (enableRegionMatching && workerRegion) {
        const sortedIPs = getSmartRegionSelection(workerRegion, availableIPs);
        if (sortedIPs.length > 0) {
            const selectedIP = sortedIPs[0];
            return selectedIP;
        }
    }

    return availableIPs[0];
}

//////////////////////////////////////////////////////////////////////////stall参数////////////////////////////////////////////////////////////////////////

// 15秒心跳, 8秒无数据认为stall, 连续8次stall重连, 最多重连24次

const KEEPALIVE = 15000, STALL_TIMEOUT = 8000, MAX_STALL = 12, MAX_RECONNECT = 24;

//////////////////////////////////////////////////////////////////////////主要架构////////////////////////////////////////////////////////////////////////

export default {

async fetch(request) {

const url = new URL(request.url);

我的SOCKS5账号 = url.searchParams.get('socks5') || url.searchParams.get('http');

启用SOCKS5全局代理 = url.searchParams.has('globalproxy') || 启用SOCKS5全局代理;

// ========== 修改部分开始 ==========
// 优先检测Worker所在地区
if (!currentWorkerRegion) {
    currentWorkerRegion = await detectWorkerRegion(request);
}

// 检查是否显式指定了proxyip参数（保持原有功能）
let useFixedProxyIP = false;

if (url.searchParams.has('proxyip')) {
    代理IP = url.searchParams.get('proxyip');
    useFixedProxyIP = true;
} else if (url.pathname.toLowerCase().includes('/proxyip=')) {
    代理IP = url.pathname.toLowerCase().split('/proxyip=')[1];
    useFixedProxyIP = true;
} else if (url.pathname.toLowerCase().includes('/proxyip.')) {
    代理IP = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
    useFixedProxyIP = true;
} else if (url.pathname.toLowerCase().includes('/pyip=')) {
    代理IP = url.pathname.toLowerCase().split('/pyip=')[1];
    useFixedProxyIP = true;
} else if (url.pathname.toLowerCase().includes('/ip=')) {
    代理IP = url.pathname.toLowerCase().split('/ip=')[1];
    useFixedProxyIP = true;
} else {
    // path中没有指定proxyip时，使用地区自适应逻辑
    const bestIP = await getBestBackupIP(currentWorkerRegion);
    if (bestIP) {
        代理IP = bestIP.domain;
        console.log(`自动选择ProxyIP: ${代理IP} (地区: ${bestIP.regionCode})`);
    } else {
        // 如果没有匹配的备用IP，使用默认逻辑
        代理IP = 代理IP ? 代理IP : request.cf.colo + '.PrOxYp.CmLiuSsSs.nEt';
    }
}
// ====================

if (url.pathname.toLowerCase().includes('/socks5=') || (url.pathname.includes('/s5=')) || (url.pathname.includes('/gs5='))) {

我的SOCKS5账号 = url.pathname.split('5=')[1];

启用SOCKS5代理 = 'socks5';

启用SOCKS5全局代理 = url.pathname.includes('/gs5=') ? true : 启用SOCKS5全局代理;

} else if (url.pathname.toLowerCase().includes('/http=')) {

我的SOCKS5账号 = url.pathname.split('/http=')[1];

启用SOCKS5代理 = 'http';

} else if (url.pathname.toLowerCase().includes('/socks://') || url.pathname.toLowerCase().includes('/socks5://') || url.pathname.toLowerCase().includes('/http://')) {

启用SOCKS5代理 = (url.pathname.includes('/http://')) ? 'http' : 'socks5';

我的SOCKS5账号 = url.pathname.split('://')[1].split('#')[0];

if (我的SOCKS5账号.includes('@')) {

const lastAtIndex = 我的SOCKS5账号.lastIndexOf('@');

let userPassword = 我的SOCKS5账号.substring(0, lastAtIndex).replaceAll('%3D', '=');

const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;

if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);

我的SOCKS5账号 = `${userPassword}@${我的SOCKS5账号.substring(lastAtIndex + 1)}`;

}

启用SOCKS5全局代理 = true;

}

if (我的SOCKS5账号) {

try {

获取SOCKS5账号(我的SOCKS5账号);

启用SOCKS5代理 = url.searchParams.get('http') ? 'http' : 启用SOCKS5代理;

} catch (err) {

启用SOCKS5代理 = null;

}

} else {

启用SOCKS5代理 = null;

}

if (request.headers.get('Upgrade') !== 'websocket') return new Response('Hello World!', { status: 200 });

const { 0: client, 1: server } = new WebSocketPair();

server.accept();

handleConnection(server, request);

return new Response(null, { status: 101, webSocket: client });

}

};

function buildUUID(arr, start) {
    return Array.from(arr.slice(start, start + 16)).map(n => n.toString(16).padStart(2, '0')).join('').replace(/(.{8})(.{4})(.{4})(.{4})(.{12})/, '$1-$2-$3-$4-$5');
}

function handleConnection(ws, request) {
    let socket, writer, reader, info;
    let isFirstMsg = true, bytesReceived = 0, stallCount = 0, reconnectCount = 0;
    let lastData = Date.now();
    const timers = {};
    const dataBuffer = [];
    let protocolType = null; // 'vless' 或 'trojan'

    // 获取 early data (用于Trojan协议)
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

    async function detectProtocol(data) {
        const bytes = new Uint8Array(data);
        
        // 尝试检测Trojan协议 (56字节密码 + \r\n)
        if (bytes.byteLength >= 58 && bytes[56] === 0x0d && bytes[57] === 0x0a) {
            return 'trojan';
        }
        
        // 默认为VLESS协议
        return 'vless';
    }

    async function processVlessHandshake(data) {
        const bytes = new Uint8Array(data);
        ws.send(new Uint8Array([bytes[0], 0]));
        if (FIXED_UUID && buildUUID(bytes, 1) !== FIXED_UUID) throw new Error('Auth failed');
        const { host, port, payload } = extractVlessAddress(bytes);
        if (host.includes(atob('c3BlZWQuY2xvdWRmbGFyZS5jb20='))) throw new Error('Access');
        const sock = await createConnection(host, port);
        await sock.opened;
        const w = sock.writable.getWriter();
        if (payload.length) await w.write(payload);
        return { socket: sock, writer: w, reader: sock.readable.getReader(), info: { host, port } };
    }

    async function processTrojanHandshake(data) {
        const bytes = new Uint8Array(data);
        
        if (bytes.byteLength < 56) {
            throw new Error("invalid data");
        }
        
        let crLfIndex = 56;
        if (bytes[56] !== 0x0d || bytes[57] !== 0x0a) {
            throw new Error("invalid header format (missing CR LF)");
        }
        
        const password = new TextDecoder().decode(bytes.slice(0, crLfIndex));
        if (FIXED_TROJAN_PASSWORD && password !== FIXED_TROJAN_PASSWORD) {
            throw new Error("invalid password");
        }

        const socks5DataBuffer = bytes.slice(crLfIndex + 2);
        if (socks5DataBuffer.byteLength < 6) {
            throw new Error("invalid SOCKS5 request data");
        }

        const view = new DataView(socks5DataBuffer.buffer, socks5DataBuffer.byteOffset, socks5DataBuffer.byteLength);
        const cmd = view.getUint8(0);
        if (cmd !== 1) {
            throw new Error("unsupported command, only TCP (CONNECT) is allowed");
        }

        const atype = view.getUint8(1);
        let addressLength = 0;
        let addressIndex = 2;
        let host = "";
        
        switch (atype) {
            case 1: // IPv4
                addressLength = 4;
                host = Array.from(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
                break;
            case 3: // Domain
                addressLength = socks5DataBuffer[addressIndex++];
                host = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
                break;
            case 4: // IPv6
                addressLength = 16;
                const dataView = new DataView(socks5DataBuffer.buffer, socks5DataBuffer.byteOffset + addressIndex, addressLength);
                const ipv6 = [];
                for (let i = 0; i < 8; i++) {
                    ipv6.push(dataView.getUint16(i * 2).toString(16));
                }
                host = ipv6.join(":");
                break;
            default:
                throw new Error(`invalid addressType is ${atype}`);
        }

        if (!host) {
            throw new Error(`address is empty, addressType is ${atype}`);
        }

        const portIndex = addressIndex + addressLength;
        const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
        const port = new DataView(portBuffer.buffer, portBuffer.byteOffset).getUint16(0);
        const payload = socks5DataBuffer.slice(portIndex + 4);

        if (host.includes(atob('c3BlZWQuY2xvdWRmbGFyZS5jb20='))) throw new Error('Access');
        
        const sock = await createConnection(host, port);
        await sock.opened;
        const w = sock.writable.getWriter();
        if (payload.length) await w.write(payload);
        return { socket: sock, writer: w, reader: sock.readable.getReader(), info: { host, port } };
    }

    async function createConnection(host, port) {
        let sock;
        if (启用SOCKS5代理 == 'socks5' && 启用SOCKS5全局代理) {
            sock = await socks5Connect(host, port);
        } else if (启用SOCKS5代理 == 'http' && 启用SOCKS5全局代理) {
            sock = await httpConnect(host, port);
        } else {
            try {
                sock = connect({ hostname: host, port });
                await sock.opened;
            } catch {
                if (启用SOCKS5代理 == 'socks5') {
                    sock = await socks5Connect(host, port);
                } else if (启用SOCKS5代理 == 'http') {
                    sock = await httpConnect(host, port);
                } else {
                    const [代理IP地址, 代理IP端口] = await 解析地址端口(代理IP);
                    sock = connect({ hostname: 代理IP地址, port: 代理IP端口 });
                }
            }
        }
        return sock;
    }

    async function readLoop() {
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (value?.length) {
                    bytesReceived += value.length;
                    lastData = Date.now();
                    stallCount = reconnectCount = 0;
                    if (ws.readyState === 1) {
                        await ws.send(value);
                        while (dataBuffer.length && ws.readyState === 1) {
                            await ws.send(dataBuffer.shift());
                        }
                    } else {
                        dataBuffer.push(value);
                    }
                }
                if (done) {
                    console.log('Stream ended gracefully');
                    await reconnect();
                    break;
                }
            }
        } catch (err) {
            console.error('Read error:', err.message);
            if (err.message.includes('reset') || err.message.includes('broken')) {
                console.log('Server closed connection, attempting reconnect');
                await reconnect();
            } else {
                cleanup();
                ws.close(1006, 'Connection abnormal');
            }
        }
    }

    async function reconnect() {
        if (!info || ws.readyState !== 1 || reconnectCount >= MAX_RECONNECT) {
            cleanup();
            ws.close(1011, 'Reconnection failed');
            return;
        }
        reconnectCount++;
        console.log(`Reconnecting (attempt ${reconnectCount})...`);
        try {
            cleanupSocket();
            await new Promise(resolve => setTimeout(resolve, 30 * Math.pow(2, reconnectCount) + Math.random() * 5));
            const sock = connect({ hostname: info.host, port: info.port });
            await sock.opened;
            socket = sock;
            writer = sock.writable.getWriter();
            reader = sock.readable.getReader();
            lastData = Date.now();
            stallCount = 0;
            console.log('Reconnected successfully');
            while (dataBuffer.length && ws.readyState === 1) {
                await writer.write(dataBuffer.shift());
            }
            readLoop();
        } catch (err) {
            console.error('Reconnect failed:', err.message);
            setTimeout(reconnect, 1000);
        }
    }

    function startTimers() {
        timers.keepalive = setInterval(async () => {
            if (Date.now() - lastData > KEEPALIVE) {
                try {
                    await writer.write(new Uint8Array(0));
                    lastData = Date.now();
                } catch (e) {
                    console.error('Keepalive failed:', e.message);
                    reconnect();
                }
            }
        }, KEEPALIVE / 3);
        timers.health = setInterval(() => {
            if (bytesReceived && Date.now() - lastData > STALL_TIMEOUT) {
                stallCount++;
                console.log(`Stall detected (${stallCount}/${MAX_STALL}), ${Date.now() - lastData}ms since last data`);
                if (stallCount >= MAX_STALL) reconnect();
            }
        }, STALL_TIMEOUT / 2);
    }

    function cleanupSocket() {
        try {
            writer?.releaseLock();
            reader?.releaseLock();
            socket?.close();
        } catch { }
    }

    function cleanup() {
        Object.values(timers).forEach(clearInterval);
        cleanupSocket();
    }

    // 处理 early data
    function processEarlyData(earlyDataHeader) {
        if (!earlyDataHeader) return null;
        try {
            const base64Str = earlyDataHeader.replace(/-/g, "+").replace(/_/g, "/");
            const decode = atob(base64Str);
            const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
            return arryBuffer;
        } catch (error) {
            return null;
        }
    }

    ws.addEventListener('message', async evt => {
        try {
            if (isFirstMsg) {
                isFirstMsg = false;
                
                // 合并 early data 和第一条消息
                let firstData = evt.data;
                const earlyData = processEarlyData(earlyDataHeader);
                if (earlyData) {
                    const combined = new Uint8Array(earlyData.length + firstData.byteLength);
                    combined.set(earlyData);
                    combined.set(new Uint8Array(firstData), earlyData.length);
                    firstData = combined.buffer;
                }
                
                // 检测协议类型
                protocolType = await detectProtocol(firstData);
                console.log(`Detected protocol: ${protocolType}`);
                
                // 根据协议类型处理握手
                if (protocolType === 'trojan') {
                    ({ socket, writer, reader, info } = await processTrojanHandshake(firstData));
                } else {
                    ({ socket, writer, reader, info } = await processVlessHandshake(firstData));
                }
                
                startTimers();
                readLoop();
            } else {
                lastData = Date.now();
                if (socket && writer) {
                    await writer.write(evt.data);
                } else {
                    dataBuffer.push(evt.data);
                }
            }
        } catch (err) {
            console.error('Connection error:', err.message);
            cleanup();
            ws.close(1006, 'Connection abnormal');
        }
    });

    ws.addEventListener('close', cleanup);
    ws.addEventListener('error', cleanup);
}

function extractVlessAddress(bytes) {
    const offset1 = 18 + bytes[17] + 1;
    const port = (bytes[offset1] << 8) | bytes[offset1 + 1];
    const addrType = bytes[offset1 + 2];
    let offset2 = offset1 + 3, host, length;
    switch (addrType) {
        case 1:
            length = 4;
            host = bytes.slice(offset2, offset2 + length).join('.');
            break;
        case 2:
            length = bytes[offset2++];
            host = new TextDecoder().decode(bytes.slice(offset2, offset2 + length));
            break;
        case 3:
            length = 16;
            host = `[${Array.from({ length: 8 }, (_, i) =>
                ((bytes[offset2 + i * 2] << 8) | bytes[offset2 + i * 2 + 1]).toString(16)
            ).join(':')}]`;
            break;
        default:
            throw new Error('Invalid address type.');
    }
    return { host, port, payload: bytes.slice(offset2 + length) };
}

async function 获取SOCKS5账号(address) {
    const lastAtIndex = address.lastIndexOf("@");
    let [latter, former] = lastAtIndex === -1 ? [address, undefined] : [address.substring(lastAtIndex + 1), address.substring(0, lastAtIndex)];
    let username, password, hostname, port;
    if (former) {
        const formers = former.split(":");
        if (formers.length !== 2) {
            throw new Error('无效的 SOCKS 地址格式:认证部分必须是 "username:password" 的形式');
        }
        [username, password] = formers;
    }
    const latters = latter.split(":");
    if (latters.length > 2 && latter.includes("]:")) {
        port = Number(latter.split("]:")[1].replace(/[^\d]/g, ''));
        hostname = latter.split("]:")[0] + "]";
    } else if (latters.length === 2) {
        port = Number(latters.pop().replace(/[^\d]/g, ''));
        hostname = latters.join(":");
    } else {
        port = 80;
        hostname = latter;
    }

    if (isNaN(port)) {
        throw new Error('无效的 SOCKS 地址格式:端口号必须是数字');
    }
    const regex = /^\[.*\]$/;
    if (hostname.includes(":") && !regex.test(hostname)) {
        throw new Error('无效的 SOCKS 地址格式:IPv6 地址必须用方括号括起来,如 [2001:db8::1]');
    }
    return { username, password, hostname, port };
}

async function 解析地址端口(proxyIP) {
    proxyIP = proxyIP.toLowerCase();
    let 地址 = proxyIP, 端口 = 443;
    if (proxyIP.includes('.tp')) {
        const tpMatch = proxyIP.match(/\.tp(\d+)/);
        if (tpMatch) 端口 = parseInt(tpMatch[1], 10);
        return [地址, 端口];
    }
    if (proxyIP.includes(']:')) {
        const parts = proxyIP.split(']:');
        地址 = parts[0] + ']';
        端口 = parseInt(parts[1], 10) || 端口;
    } else if (proxyIP.includes(':') && !proxyIP.startsWith('[')) {
        const colonIndex = proxyIP.lastIndexOf(':');
        地址 = proxyIP.slice(0, colonIndex);
        端口 = parseInt(proxyIP.slice(colonIndex + 1), 10) || 端口;
    }
    return [地址, 端口];
}

async function httpConnect(addressRemote, portRemote) {
    const { username, password, hostname, port } = await 获取SOCKS5账号(我的SOCKS5账号);
    const sock = await connect({ hostname, port });
    const authHeader = username && password ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n` : '';
    const connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n` +
        `Host: ${addressRemote}:${portRemote}\r\n` +
        authHeader +
        `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n` +
        `Proxy-Connection: Keep-Alive\r\n` +
        `Connection: Keep-Alive\r\n\r\n`;
    const writer = sock.writable.getWriter();
    try {
        await writer.write(new TextEncoder().encode(connectRequest));
    } catch (err) {
        throw new Error(`发送HTTP CONNECT请求失败: ${err.message}`);
    } finally {
        writer.releaseLock();
    }
    const reader = sock.readable.getReader();
    let responseBuffer = new Uint8Array(0);
    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) throw new Error('HTTP代理连接中断');
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            const respText = new TextDecoder().decode(responseBuffer);
            if (respText.includes('\r\n\r\n')) {
                const headersEndPos = respText.indexOf('\r\n\r\n') + 4;
                const headers = respText.substring(0, headersEndPos);

                if (!headers.startsWith('HTTP/1.1 200') && !headers.startsWith('HTTP/1.0 200')) {
                    throw new Error(`HTTP代理连接失败: ${headers.split('\r\n')[0]}`);
                }
                if (headersEndPos < responseBuffer.length) {
                    const remainingData = responseBuffer.slice(headersEndPos);
                    const { readable, writable } = new TransformStream();
                    new ReadableStream({
                        start(controller) {
                            controller.enqueue(remainingData);
                        }
                    }).pipeTo(writable).catch(() => { });
                    sock.readable = readable;
                }
                break;
            }
        }
    } catch (err) {
        throw new Error(`处理HTTP代理响应失败: ${err.message}`);
    } finally {
        reader.releaseLock();
    }
    return sock;
}

async function socks5Connect(targetHost, targetPort) {
    const parsedSocks5Address = await 获取SOCKS5账号(我的SOCKS5账号);
    const { username, password, hostname, port } = parsedSocks5Address;
    const sock = connect({
        hostname: hostname,
        port: port
    });
    await sock.opened;
    const w = sock.writable.getWriter();
    const r = sock.readable.getReader();
    await w.write(new Uint8Array([5, 2, 0, 2]));
    const auth = (await r.read()).value;
    if (auth[1] === 2 && username) {
        const user = new TextEncoder().encode(username);
        const pass = new TextEncoder().encode(password);
        await w.write(new Uint8Array([1, user.length, ...user, pass.length, ...pass]));
        await r.read();
    }
    const domain = new TextEncoder().encode(targetHost);
    await w.write(new Uint8Array([5, 1, 0, 3, domain.length, ...domain,
        targetPort >> 8, targetPort & 0xff
    ]));
    await r.read();
    w.releaseLock();
    r.releaseLock();
    return sock;
}