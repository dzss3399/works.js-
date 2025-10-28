/*
// 代码基本都抄的CM和天书大佬的项目，在此感谢各位大佬的无私奉献。
// 支持xhttp和trojan和vless和ss协议,ss协议无密码
// 同时写s5和proxyall相当于写gs5，http同理，nat64也同理，只写proxyall为纯直连模式，
// 支持的参数：ip，proxyip，pyip，socks5，s5，gs5，s5all，nat64, nat64all, gnat64, http，ghttp，httpall，proxyall，globalproxy
// 所有ipv6地址需要[ipv6]，包括路径里的nat64前缀
// 有proxyall参数即为全局代理，如果只写proxyall为全走直连
// path路径示例：/?ed=2560&proxyip=ProxyIP.SG.CMLiussss.net:443&socks5=user:passsword@host:443&http=user:passsword@host:443&proxyall=1
// 多个参数键值对之间用&连接，单个参数键和值用=连接
// 比如socks5=user:passsword@host:443可以写成socks5://user:passsword@host:443
// proxyip支持域名tp端口模式，可不用单独写端口号
// ?ed=2560为开启websocket连接0rtt模式可节约一个rtt延迟，singbox好像不支持
// ws模式的vless导入链接：vless://{这里写uuid}@104.16.40.11:2053?encryption=none&security=tls&sni={这里写域名}&alpn=http%2F1.1&fp=chrome&type=ws&host={这里写域名}#vless
// ws模式的trojan导入链接：trojan://{这里写密码}@104.16.40.11:2053?security=tls&sni={这里写域名}&alpn=http%2F1.1&fp=chrome&allowInsecure=1&type=ws&host={这里写域名}#trojan
// ws模式的ss协议只能纯手搓，完全可以参考trojan的设置
// xhttp模式的vless导入链接：vless://{这里写uuid}@104.16.40.11:2053?encryption=none&security=tls&sni={这里写域名}&alpn=h2&fp=chrome&allowInsecure=1&type=xhttp&host={这里写域名}&mode=stream-one#xhttp
// 复制协议开头的导入链接导入再手动修改即可
*/
import {connect} from 'cloudflare:sockets';
const uuid = 'd342d11e-d424-4583-b36e-524ab1f0afa4';//vless使用的uuid
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥，需要自己计算，当前设置为密码666的密钥
//**警告**:trojan使用的sha224密钥计算网址：https://www.lzltool.com/data-sha224
const passWordSha224 = '509eece82eb6910bebef9af9496092d3244b6c0d69ef3aaa4b12c565';
// ---------------------------------------------------------------------------------
// 理论最大带宽计算公式 (Theoretical Max Bandwidth Calculation):
//    - 速度上限 (Mbps) = (bufferSize (字节) / flushTime (毫秒)) * 0.008
//    - 示例: (512 * 1024 字节 / 10 毫秒) * 0.008 ≈ 419 Mbps
//    - 在此模式下，这两个参数共同构成了一个精确的速度限制器。
// ---------------------------------------------------------------------------------
/** 缓冲发送模式开关。true: 启用缓冲层，聚合发送可降低发送send()调用开销，但是会增加数据转发延迟。false: 不使用缓冲层。*/
const userBufferer = true;
/** 缓冲区最大大小。用于计算速度上限。*/
const bufferSize = 512 * 1024; // 512KB
/** 发送调用刷新时间(毫秒)。设定固定的发送频率以控制速度。*/
/**- **警告**: 设置过低  会因定时器精度和高频创建/销毁开销导致 CPU 负担加重。*/
const flushTime = 10; // 10ms
// ---------------------------------------------------------------------------------
/** TCPsocket并发获取，可提高tcp连接成功率*/
const concurrentOnlyDomain = false;//只对域名并发开关
/**- **警告**: snippets只能设置为1，worker最大支持6，超过6没意义*/
const concurrency = 4;//socket获取并发数
// ---------------------------------------------------------------------------------
//三者的socket获取顺序，全局模式下为这三个的顺序，非全局为：直连>socks>http>nat64>proxyip>finallyProxyHost
/**- **警告**: snippets只支持最大两次connect，所以snippets全局nat64不能使用域名访问，snippets访问cf失败的备用只有第一个有效*/
const proxyStrategyOrder = ['socks', 'http', 'nat64'];
const dohEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query'];
const dohNatEndpoints = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const dohFetchOptions = {method: 'POST', headers: {'content-type': 'application/dns-message'}};
const proxyIpAddrs = {EU: 'ProxyIP.DE.CMLiussss.net', AS: 'ProxyIP.SG.CMLiussss.net', JP: 'ProxyIP.JP.CMLiussss.net', US: 'ProxyIP.US.CMLiussss.net'};//分区域proxyip
const finallyProxyHost = 'ProxyIP.CMLiussss.net';//兜底proxyip
const coloRegions = {
    JP: new Set(['FUK', 'ICN', 'KIX', 'NRT', 'OKA']),
    EU: new Set([
        'ACC', 'ADB', 'ALA', 'ALG', 'AMM', 'AMS', 'ARN', 'ATH', 'BAH', 'BCN', 'BEG', 'BGW', 'BOD', 'BRU', 'BTS', 'BUD', 'CAI',
        'CDG', 'CPH', 'CPT', 'DAR', 'DKR', 'DMM', 'DOH', 'DUB', 'DUR', 'DUS', 'DXB', 'EBB', 'EDI', 'EVN', 'FCO', 'FRA', 'GOT',
        'GVA', 'HAM', 'HEL', 'HRE', 'IST', 'JED', 'JIB', 'JNB', 'KBP', 'KEF', 'KWI', 'LAD', 'LED', 'LHR', 'LIS', 'LOS', 'LUX',
        'LYS', 'MAD', 'MAN', 'MCT', 'MPM', 'MRS', 'MUC', 'MXP', 'NBO', 'OSL', 'OTP', 'PMO', 'PRG', 'RIX', 'RUH', 'RUN', 'SKG',
        'SOF', 'STR', 'TBS', 'TLL', 'TLV', 'TUN', 'VIE', 'VNO', 'WAW', 'ZAG', 'ZRH']),
    AS: new Set([
        'ADL', 'AKL', 'AMD', 'BKK', 'BLR', 'BNE', 'BOM', 'CBR', 'CCU', 'CEB', 'CGK', 'CMB', 'COK', 'DAC', 'DEL', 'HAN', 'HKG',
        'HYD', 'ISB', 'JHB', 'JOG', 'KCH', 'KHH', 'KHI', 'KTM', 'KUL', 'LHE', 'MAA', 'MEL', 'MFM', 'MLE', 'MNL', 'NAG', 'NOU',
        'PAT', 'PBH', 'PER', 'PNH', 'SGN', 'SIN', 'SYD', 'TPE', 'ULN', 'VTE'])
};
const coloToProxyMap = new Map(Object.entries(coloRegions).flatMap(([region, colos]) => Array.from(colos, colo => [colo, proxyIpAddrs[region]])));
const uuidView = new DataView(new Uint8Array(uuid.match(/[0-9a-f]{2}/gi).map(b => parseInt(b, 16))).buffer);
const [uuidPart1, uuidPart2, uuidPart3, uuidPart4] = [0, 4, 8, 12].map(offset => uuidView.getUint32(offset));
const hashview = new DataView(new TextEncoder().encode(passWordSha224).buffer);
const hashParts = Array.from({length: 14}, (_, i) => hashview.getUint32(i * 4));
const [textEncoder, textDecoder, socks5Init, httpHeaderEnd] = [new TextEncoder(), new TextDecoder(), new Uint8Array([5, 2, 0, 2]), new Uint8Array([13, 10, 13, 10])];
const html = `<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.25.3</center></body></html>`;
const binaryAddrToString = (addrType, addrBytes) => {
    if (addrType === 3) return textDecoder.decode(addrBytes);
    if (addrType === 1) return `${addrBytes[0]}.${addrBytes[1]}.${addrBytes[2]}.${addrBytes[3]}`;
    if (addrType === 4) {
        const view = new DataView(addrBytes.buffer, addrBytes.byteOffset, addrBytes.byteLength);
        let ipv6 = view.getUint16(0).toString(16);
        for (let i = 1; i < 8; i++) ipv6 += ':' + view.getUint16(i * 2).toString(16);
        return `[${ipv6}]`;
    }
};
const parseHostPort = (addr, defaultPort) => {
    if (addr.startsWith('[')) {
        const sepIndex = addr.indexOf(']:');
        if (sepIndex !== -1) {
            const host = addr.substring(0, sepIndex + 1);
            const port = parseInt(addr.substring(sepIndex + 2), 10);
            if (!isNaN(port)) return [host, port];
        }
        return [addr, defaultPort];
    }
    const tpIndex = addr.indexOf('.tp');
    const lastColon = addr.lastIndexOf(':');
    if (tpIndex !== -1 && lastColon === -1) {
        const port = addr.substring(tpIndex + 3, addr.indexOf('.', tpIndex + 3));
        if (!isNaN(port)) return [addr, port];
    }
    if (lastColon === -1) return [addr, defaultPort];
    const host = addr.substring(0, lastColon);
    const port = parseInt(addr.substring(lastColon + 1), 10);
    return !isNaN(port) ? [host, port] : [host, defaultPort];
};
const parseAuthString = (authParam) => {
    let username, password, hostStr;
    const atIndex = authParam.lastIndexOf('@');
    if (atIndex === -1) {hostStr = authParam} else {
        const cred = authParam.substring(0, atIndex);
        hostStr = authParam.substring(atIndex + 1);
        const colonIndex = cred.indexOf(':');
        if (colonIndex === -1) {username = cred} else {
            username = cred.substring(0, colonIndex);
            password = cred.substring(colonIndex + 1);
        }
    }
    const [hostname, port] = parseHostPort(hostStr, 1080);
    return {username, password, hostname, port};
};
const isIPv4optimized = (str) => {
    if (str.length > 15 || str.length < 7) return false;
    let part = 0, dots = 0, partLen = 0;
    for (let i = 0; i < str.length; i++) {
        const charCode = str.charCodeAt(i);
        if (charCode === 46) {
            dots++;
            if (dots > 3 || partLen === 0 || (str.charCodeAt(i - 1) === 48 && partLen > 1)) return false;
            part = 0;
            partLen = 0;
        } else if (charCode >= 48 && charCode <= 57) {
            partLen++;
            part = part * 10 + (charCode - 48);
            if (part > 255 || partLen > 3) return false;
        } else {return false}
    }
    return !(dots !== 3 || partLen === 0 || (str.charCodeAt(str.length - partLen) === 48 && partLen > 1));
};
const isDomainName = (inputStr) => {
    if (!concurrentOnlyDomain) return true;
    if (!inputStr || inputStr[0] === '[') return false;
    if (inputStr[0].charCodeAt(0) < 48 || inputStr[0].charCodeAt(0) > 57) return true;
    return !isIPv4optimized(inputStr);
};
const createConnect = (hostname, port) => {
    const socket = connect({hostname, port});
    return socket.opened.then(() => socket);
};
const concurrentConnect = (hostname, port, addrType) => {
    if (concurrentOnlyDomain && addrType !== 3) return createConnect(hostname, port);
    return Promise.any(Array(concurrency).fill(null).map(() => createConnect(hostname, port)));
};
const connectViaSocksProxy = async (targetAddrType, targetPortNum, socksAuth, targetAddrBytes) => {
    const addrType = isDomainName(socksAuth.hostname) ? 3 : 0;
    const socksSocket = await concurrentConnect(socksAuth.hostname, socksAuth.port, addrType);
    const writer = socksSocket.writable.getWriter();
    const reader = socksSocket.readable.getReader();
    try {
        await writer.write(socks5Init);
        const {value: authResponse} = await reader.read();
        if (!authResponse || authResponse[0] !== 5 || authResponse[1] === 0xFF) return null;
        if (authResponse[1] === 2) {
            if (!socksAuth.username) return null;
            const userBytes = textEncoder.encode(socksAuth.username);
            const passBytes = textEncoder.encode(socksAuth.password || '');
            await writer.write(new Uint8Array([1, userBytes.length, ...userBytes, passBytes.length, ...passBytes]));
            const {value: authResult} = await reader.read();
            if (!authResult || authResult[0] !== 1 || authResult[1] !== 0) return null;
        } else if (authResponse[1] !== 0) {return null}
        await writer.write(new Uint8Array([
            5, 1, 0, targetAddrType,
            ...(targetAddrType === 3 ? [targetAddrBytes.length] : []),
            ...targetAddrBytes,
            targetPortNum >> 8,
            targetPortNum & 0xff
        ]));
        const {value: finalResponse} = await reader.read();
        if (!finalResponse || finalResponse[1] !== 0) return null;
        return socksSocket;
    } finally {writer?.releaseLock(), reader?.releaseLock()}
};
const findSequence = (chunks) => {
    const seqLen = httpHeaderEnd.length;
    if (seqLen === 0) return 0;
    let totalLen = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
    if (totalLen < seqLen) return -1;
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) {
        combined.set(chunk, offset);
        offset += chunk.length;
    }
    for (let i = 0; i <= combined.length - seqLen; i++) {
        let found = true;
        for (let j = 0; j < seqLen; j++) {
            if (combined[i + j] !== httpHeaderEnd[j]) {
                found = false;
                break;
            }
        }
        if (found) return i;
    }
    return -1;
};
const connectViaHttpProxy = async (targetAddrType, targetPortNum, httpAuth, targetAddrBytes) => {
    const {username, password, hostname, port} = httpAuth;
    const addrType = isDomainName(hostname) ? 3 : 0;
    const proxySocket = await concurrentConnect(hostname, port, addrType);
    const writer = proxySocket.writable.getWriter();
    const httpHost = binaryAddrToString(targetAddrType, targetAddrBytes);
    const requestHeaders = [`CONNECT ${httpHost}:${targetPortNum} HTTP/1.1`, `Host: ${httpHost}:${targetPortNum}`];
    if (username) requestHeaders.push(`Proxy-Authorization: Basic ${btoa(`${username}:${password || ''}`)}`);
    requestHeaders.push('Proxy-Connection: Keep-Alive', 'Connection: Keep-Alive', '\r\n');
    await writer.write(textEncoder.encode(requestHeaders.join('\r\n')));
    writer.releaseLock();
    const reader = proxySocket.readable.getReader();
    const chunks = [];
    let headerFound = false;
    try {
        while (!headerFound) {
            const {value, done} = await reader.read();
            if (done) break;
            chunks.push(value);
            if (findSequence(chunks) !== -1) headerFound = true;
        }
        if (!headerFound) {
            await proxySocket.close();
            return null;
        }
        let totalLen = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
        const combined = new Uint8Array(totalLen);
        let offset = 0;
        for (const chunk of chunks) {
            combined.set(chunk, offset);
            offset += chunk.length;
        }
        const responseStr = textDecoder.decode(combined.subarray(0, 20));
        if (!responseStr.startsWith('HTTP/1.1 200') && !responseStr.startsWith('HTTP/1.0 200')) {
            await proxySocket.close();
            return null;
        }
        reader.releaseLock();
        return proxySocket;
    } catch {
        reader.releaseLock();
        await proxySocket.close();
        return null;
    }
};
const parseAddressAndPort = (buffer, offset, addrType) => {
    const addressLength = addrType === 3 ? buffer[offset++] : addrType === 1 ? 4 : addrType === 4 ? 16 : null;
    if (addressLength === null) return null;
    const newOffset = offset + addressLength;
    if (newOffset > buffer.length) return null;
    const targetAddrBytes = buffer.subarray(offset, newOffset);
    return {targetAddrBytes, dataOffset: newOffset};
};
const parseRequestData = (firstChunk) => {
    const dataView = new DataView(firstChunk.buffer);
    if (dataView.getUint32(1) !== uuidPart1 || dataView.getUint32(5) !== uuidPart2 ||
        dataView.getUint32(9) !== uuidPart3 || dataView.getUint32(13) !== uuidPart4) {return null}
    let offset = 19 + firstChunk[17];
    const port = dataView.getUint16(offset);
    let addrType = firstChunk[offset + 2];
    if (addrType === 2 || addrType === 3) addrType += 1;
    const addressInfo = parseAddressAndPort(firstChunk, offset + 3, addrType);
    if (!addressInfo) return null;
    return {addrType, ...addressInfo, port, isDns: port === 53};
};
const parseTransparent = (firstChunk) => {
    const dataView = new DataView(firstChunk.buffer);
    for (let i = 0; i < 14; i++) if (dataView.getUint32(i * 4) !== hashParts[i]) return null;
    const addrType = firstChunk[59];
    const addressInfo = parseAddressAndPort(firstChunk, 60, addrType);
    if (!addressInfo) return null;
    const port = dataView.getUint16(addressInfo.dataOffset);
    return {addrType, ...addressInfo, port, dataOffset: addressInfo.dataOffset + 4, isDns: port === 53};
};
const parseShadow = (firstChunk) => {
    const addrType = firstChunk[0];
    const addressInfo = parseAddressAndPort(firstChunk, 1, addrType);
    if (!addressInfo) return null;
    const port = (firstChunk[addressInfo.dataOffset] << 8) | firstChunk[addressInfo.dataOffset + 1];
    return {addrType, ...addressInfo, port, dataOffset: addressInfo.dataOffset + 2, isDns: port === 53};
};
const ipv4ToNat64Ipv6 = (ipv4Address, nat64Prefixes) => {
    const parts = ipv4Address.split('.');
    const hex = parts.map(part => {
        const num = parseInt(part, 10);
        return num.toString(16).padStart(2, '0');
    });
    return `[${nat64Prefixes}${hex[0]}${hex[1]}:${hex[2]}${hex[3]}]`;
};
const concurrentDnsResolve = async (hostname, recordType) => {
    try {
        const dnsResult = await Promise.any(dohNatEndpoints.map(endpoint =>
            fetch(`${endpoint}?name=${hostname}&type=${recordType}`, {headers: {'Accept': 'application/dns-json'}}).then(response => {
                if (!response.ok) throw new Error();
                return response.json();
            })
        ));
        const answer = dnsResult.Answer || dnsResult.answer;
        if (!answer || answer.length === 0) return null;
        return answer;
    } catch {return null}
};
const connectNat64 = async (addrType, port, nat64Auth, targetAddrBytes, proxyAll) => {
    const nat64Prefixes = nat64Auth.startsWith('[') ? nat64Auth.slice(1, -1) : nat64Auth;
    if (!proxyAll) return await concurrentConnect(ipv4ToNat64Ipv6('104.19.65.36', nat64Prefixes), port, 4);
    if (addrType === 4) return null;
    const hostname = binaryAddrToString(addrType, targetAddrBytes);
    if (addrType === 1) return await concurrentConnect(ipv4ToNat64Ipv6(hostname, nat64Prefixes), port, 4);
    if (addrType === 3) {
        const answer = await concurrentDnsResolve(hostname, 'A');
        if (!answer) return null;
        const aRecord = answer.find(record => record.type === 1);
        if (aRecord && aRecord.data) return await concurrentConnect(ipv4ToNat64Ipv6(aRecord.data, nat64Prefixes), port, 4);
    }
    return null;
};
const williamResult = async (william) => {
    const answer = await concurrentDnsResolve(william, 'TXT');
    if (!answer) return null;
    const txtRecords = answer.filter(record => record.type === 16).map(record => record.data);
    if (txtRecords.length === 0) return null;
    let txtData = txtRecords[0];
    if (txtData.startsWith('"') && txtData.endsWith('"')) txtData = txtData.slice(1, -1);
    const prefixes = txtData.replace(/\\010/g, ',').replace(/\n/g, ',').split(',').map(s => s.trim()).filter(Boolean);
    if (prefixes.length === 0) return null;
    return prefixes;
};
const strategyExecutorMap = new Map([
    [0, async ({addrType, port, targetAddrBytes}) => {
        const hostname = binaryAddrToString(addrType, targetAddrBytes);
        return concurrentConnect(hostname, port, addrType);
    }],
    [1, async ({addrType, port, targetAddrBytes}, param) => {
        const socksAuth = parseAuthString(param);
        return connectViaSocksProxy(addrType, port, socksAuth, targetAddrBytes);
    }],
    [2, async ({addrType, port, targetAddrBytes}, param) => {
        const httpAuth = parseAuthString(param);
        return connectViaHttpProxy(addrType, port, httpAuth, targetAddrBytes);
    }],
    [3, async (_parsedRequest, param) => {
        if (param.includes('.william')) {
            const resolvedIps = await williamResult(param);
            if (!resolvedIps || resolvedIps.length === 0) return null;
            const connectionPromises = resolvedIps.map(ip => {
                const [host, port] = parseHostPort(ip, 443);
                return createConnect(host, port);
            });
            try {return await Promise.any(connectionPromises)} catch {return null;}
        } else {
            const [host, port] = parseHostPort(param, 443);
            const addrType = isDomainName(host) ? 3 : 0;
            return concurrentConnect(host, port, addrType);
        }
    }],
    [4, async (_parsedRequest, _param) => {
        return concurrentConnect(finallyProxyHost, 443, 3);
    }],
    [5, async ({addrType, port, targetAddrBytes}, param) => {
        const {nat64Auth, proxyAll} = param;
        return connectNat64(addrType, port, nat64Auth, targetAddrBytes, proxyAll);
    }]
]);
const paramRegex = /(gs5|s5all|ghttp|gnat64|nat64all|httpall|s5|socks|http|ip|nat64)(?:=|:\/\/|%3A%2F%2F)([^&]+)|(proxyall|globalproxy)/gi;
const prepareProxyConfig = (request) => {
    const url = request.url.substring(request.url.indexOf('/', 10) + 1);
    const cleanUrl = (url.endsWith('/') || url.endsWith('=')) ? url.slice(0, -1) : url;
    const params = new Map();
    let match;
    while ((match = paramRegex.exec(cleanUrl)) !== null) {
        if (match[1] && match[2]) {
            params.set(match[1].toLowerCase(), match[2]);
        } else if (match[3]) {params.set(match[3].toLowerCase(), true)}
    }
    const gs5Param = params.get('gs5') ?? params.get('s5all');
    const ghttpParam = params.get('ghttp') ?? params.get('httpall');
    const gnat64Param = params.get('gnat64') ?? params.get('nat64all');
    const socksParam = gs5Param ?? params.get('s5') ?? params.get('socks');
    const httpParam = ghttpParam ?? params.get('http');
    const nat64Param = gnat64Param ?? params.get('nat64');
    const proxyAll = !!(gs5Param || ghttpParam || gnat64Param || params.has('proxyall') || params.has('globalproxy'));
    const strategyMap = {
        socks: socksParam ? decodeURIComponent(socksParam).split(',').filter(Boolean).map(p => ({type: 1, param: p.trim()})) : [],
        http: httpParam ? decodeURIComponent(httpParam).split(',').filter(Boolean).map(p => ({type: 2, param: p.trim()})) : [],
        nat64: nat64Param ? decodeURIComponent(nat64Param).split(',').filter(Boolean).map(p => ({type: 5, param: {nat64Auth: p.trim(), proxyAll: proxyAll}})) : []
    };
    const orderedProxyStrategies = proxyStrategyOrder.flatMap(key => strategyMap[key]);
    let strategies = [];
    if (proxyAll) {
        strategies.push(...orderedProxyStrategies);
        if (strategies.length === 0) strategies.push({type: 0});
    } else {
        const ipParam = params.get('ip');
        const proxyIpSources = [
            ...(ipParam ? decodeURIComponent(ipParam).split(',').filter(Boolean).map(p => p.trim()) : []),
            coloToProxyMap.get(request.cf?.colo) ?? proxyIpAddrs.US
        ];
        const proxyIpStrategies = proxyIpSources.map(ipString => {return {type: 3, param: ipString}});
        strategies = [{type: 0}, ...orderedProxyStrategies, ...proxyIpStrategies, {type: 4}];
    }
    return strategies;
};
const establishTcpConnection = async (parsedRequest, request) => {
    const strategies = prepareProxyConfig(request);
    for (const strategy of strategies) {
        const executor = strategyExecutorMap.get(strategy.type);
        if (!executor) continue;
        try {
            const tcpSocket = await executor(parsedRequest, strategy.param);
            if (tcpSocket) return tcpSocket;
        } catch {}
    }
    return null;
};
const dohDnsHandler = async (payload) => {
    if (payload.byteLength < 2) throw new Error();
    const dnsQueryData = payload.subarray(2);
    const resp = await Promise.any(dohEndpoints.map(endpoint =>
        fetch(endpoint, {...dohFetchOptions, body: dnsQueryData})
            .then(response => {
                if (!response.ok) throw new Error();
                return response;
            })
    ));
    const dnsQueryResult = await resp.arrayBuffer();
    const udpSize = dnsQueryResult.byteLength;
    const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
    const packet = new Uint8Array(udpSizeBuffer.length + udpSize);
    packet.set(udpSizeBuffer, 0);
    packet.set(new Uint8Array(dnsQueryResult), udpSizeBuffer.length);
    return packet;
};
const manualPipe = async (readable, writable, initialChunk) => {
    if (initialChunk?.byteLength > 0) writable.send(initialChunk);
    if (!userBufferer) {
        for await (const chunk of readable) writable.send(chunk)
        return;
    }
    const safeBufferSize = bufferSize - 4096;
    let buffer = new Uint8Array(bufferSize), offset = 0, timerId = null, resume = null;
    const flushBuffer = () => {
        offset > 0 && (writable.send(buffer.subarray(0, offset)), buffer = new Uint8Array(bufferSize), offset = 0);
        timerId && (clearTimeout(timerId), timerId = null);
        resume?.();
        resume = null;
    };
    try {
        for await (const chunk of readable) {
            if (chunk.length < 4096) {
                flushBuffer();
                writable.send(chunk);
            } else {
                buffer.set(chunk, offset);
                offset += chunk.length;
                timerId || (timerId = setTimeout(flushBuffer, flushTime));
                if (offset > safeBufferSize) await new Promise(resolve => resume = resolve);
            }
        }
    } finally {
        timerId && clearTimeout(timerId);
        // @ts-ignore
        resume?.();
        flushBuffer();
    }
};
const handleWebSocketConn = async (request) => {
    const {0: clientSocket, 1: webSocket} = new WebSocketPair();
    webSocket.accept();
    const protocolHeader = request.headers.get('sec-websocket-protocol');
    // @ts-ignore
    const earlyData = protocolHeader ? Uint8Array.fromBase64(protocolHeader, {alphabet: 'base64url'}) : null;
    let messageHandler, tcpSocket;
    const closeSocket = () => {tcpSocket?.close(), webSocket?.close()};
    if (earlyData) await processChunk(earlyData).catch(() => closeSocket());
    webSocket.addEventListener("message", (event) => processChunk(event.data).catch(() => closeSocket()));
    async function processChunk(chunk) {
        if (messageHandler) return messageHandler(chunk);
        chunk = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
        let parsedRequest;
        if (chunk.length > 58 && chunk[56] === 0x0d && chunk[57] === 0x0a) {
            parsedRequest = parseTransparent(chunk);
        } else if ((parsedRequest = parseRequestData(chunk))) {
            webSocket.send(new Uint8Array([chunk[0], 0]));
        } else {parsedRequest = parseShadow(chunk)}
        if (!parsedRequest) throw new Error();
        const payload = chunk.subarray(parsedRequest.dataOffset);
        if (parsedRequest.isDns) {
            webSocket.send(await dohDnsHandler(payload));
            if (!earlyData) webSocket.close();
        } else {
            tcpSocket = await establishTcpConnection(parsedRequest, request);
            if (!tcpSocket) throw new Error();
            const tcpWriter = tcpSocket.writable.getWriter();
            if (payload.byteLength) tcpWriter.write(payload);
            manualPipe(tcpSocket.readable, webSocket, null).catch(() => closeSocket());
            messageHandler = (chunk) => tcpWriter.write(chunk);
        }
    }
    return new Response(null, {status: 101, webSocket: clientSocket});
};
const handleXhttp = async (request) => {
        const reader = request.body.getReader();
        let buffer = new Uint8Array(4096), used = 0, parsedRequest = null, responseStream;
        while (true) {
            const {value, done} = await reader.read();
            if (done) return new Response(null, {status: 500});
            if (used + value.length > buffer.length) {
                const newBuffer = new Uint8Array(Math.max(buffer.length * 2, used + value.length));
                newBuffer.set(buffer.subarray(0, used));
                buffer = newBuffer;
            }
            buffer.set(value, used);
            used += value.length;
            if (used < 48) continue;
            const currentBuffer = buffer.subarray(0, used);
            parsedRequest = parseRequestData(currentBuffer);
            if (parsedRequest) break;
        }
        if (!parsedRequest) return new Response(null, {status: 500});
        try {
            const payload = buffer.subarray(parsedRequest.dataOffset, used);
            const resVersion = new Uint8Array([buffer[0], 0]);
            if (parsedRequest.isDns) {
                const dohResult = await dohDnsHandler(payload);
                responseStream = new Uint8Array(2 + dohResult.byteLength);
                responseStream.set(resVersion, 0);
                responseStream.set(dohResult, 2);
            } else {
                const tcpSocket = await establishTcpConnection(parsedRequest, request);
                if (!tcpSocket) return new Response(null, {status: 500});
                const requestToTcp = async () => {
                    const writer = tcpSocket.writable.getWriter();
                    if (payload.byteLength) writer.write(payload);
                    writer.releaseLock();
                    reader.releaseLock();
                    await request.body.pipeTo(tcpSocket.writable);
                };
                requestToTcp().catch(() => tcpSocket.close());
                responseStream = new ReadableStream({
                    start(controller) {
                        const writable = {send: (chunk) => controller.enqueue(chunk)};
                        manualPipe(tcpSocket.readable, writable, resVersion).then(() => controller.close()).catch(err => controller.error(err));
                    }
                });
            }
            return new Response(responseStream, {headers: {'Content-Type': 'application/octet-stream', 'X-Accel-Buffering': 'no', 'Cache-Control': 'no-store'}});
        } catch {return new Response(null, {status: 500})}
    }
;
export default {
    async fetch(request) {
        if (request.method === 'POST') return handleXhttp(request);
        if (request.headers.get('Upgrade')?.toLowerCase() === 'websocket') return handleWebSocketConn(request);
        return new Response(html, {status: 404, headers: {'Content-Type': 'text/html; charset=UTF-8'}});
    }
};