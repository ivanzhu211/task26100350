# task26100350

离线 Modbus TCP 流量解码库（纯 Python 标准库，无第三方依赖）。

## 用法

```python
from modbus_pcap import decode

for event in decode("capture.pcap"):
    print(event.kind, event)
```

输入为经典 libpcap 格式抓包文件（两种字节序、微秒/纳秒两种时间戳精度均可），
链路层以太网（支持一层/两层 802.1Q），网络层 IPv4（无分片），TCP 端口 502 一侧为服务端。

## 事件类型

- `transaction`：配好对的请求/响应，含连接四元组、单元号、功能码、双方时间戳；
  功能码 1/2/3/4/5/6/15/16/23 解出起始地址、数量与逐地址值（`address_values`），
  异常响应解出异常码（`response.exception_code`）。
- `unanswered_request`：连接结束时仍未收到响应的请求。
- `orphan_response`：找不到对应请求的响应。
- `malformed_frame`：畸形帧（含原因与原始字节）。
- `stream_gap`：流缺口（连接、方向、丢失字节数）。

## 保证

- 每个输出的 Modbus 帧都是该方向 TCP 流中连续、真实发送过的一段字节；
  缺口两侧不拼接，以太网填充不计入，重传/重叠不重复计数，重叠冲突时先收到的为准。
- 缺口后丢弃残缺帧、不产出伪帧，并在同一连接内恢复后续解码。
- 流式处理：内存占用只随同时活跃的连接数增长；每个方向的乱序缓冲有上限
  （默认 1 MiB），超出部分按丢包处理。

## 测试

```
python3 -m unittest discover -s tests
```
