# task050-checksum

进程内的「文件校验和批量计算与验证服务」。维护一组命名数据块（blob，二进制字节内容存于内存），支持按 md5/sha256 计算校验和、生成清单（manifest）、并逐行批量验证清单声明的期望校验和与数据块当前内容是否一致，输出每条目的核对结果（一致 / 不一致 / 数据块缺失 / 清单行非法）与各类计数汇总。所有状态保存在进程内存中，不依赖外部服务或文件系统。

主要输入：通过 HTTP 接收 blob 注册（Base64 内容）、清单生成请求（算法 + 名称列表）、清单验证请求（清单文本）。
主要输出：blob 元数据（名称、大小、md5、sha256）、生成的清单文本、逐行验证结果与汇总计数。

## 本地命令

```bash
go build ./...          # 编译
go run . --smoke-test   # 执行内置自检后退出（不依赖外部服务）
go run . --addr :8080   # 启动 HTTP 服务
go test ./...           # 运行全部测试
```

## Docker 构建

构建脚本 `build_benzhi_docker.sh` 接受两个参数：镜像名、平台。

```bash
# amd64
bash ./build_benzhi_docker.sh go-task-benzhi:amd64 linux/amd64

# arm64
bash ./build_benzhi_docker.sh go-task-benzhi:arm64 linux/arm64
```

进入容器：

```bash
docker run -it go-task-benzhi:amd64
docker run -it go-task-benzhi:arm64
```
