### ovpn wrapper

> 适配ubuntu armv8的OpenVPN客户端

* OpenVPN 2.6.14 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO]
* library versions: OpenSSL 3.0.13 30 Jan 2024, LZO 2.10


* 一个简单的配置文件加密工具


* Gen Config(输入密码进行加密)

```shell
go run encrypt.go -in client.ovpn -out config_blob.go

```



* Build Wrapper

```shell
go build -o ovpn-wrapper_armv8 wrapper.go config_blob.go
```


* Usage(运行输入密码后启动客户端)

```shell
./ovpn-wrapper
```