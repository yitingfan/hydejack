---
layout: post
title: Server-Side Request Forgery
tags: [web 安全]
---
跨站请求伪造，ssrf，是一类描述服务器在攻击者的控制下发出请求的漏洞。这篇文章会讲到 ssrf 的影响，如何测试，风险点，修复建议和注意事项。

在深入了解 ssrf 的影响之前，先花时间了解一下这个漏洞本身。它发生在一个在线的应用需要请求外部资源的情况下。比如说，当你在 tweet 上转发这篇文章时候，在 tweet 上就会有来自于这篇文章的图片标题和描述。为了下载这些信息，tweet 服务的向这个页面发送 http 请求并提取出需要的信息。直到最近，tweet 
上被发现存在 ssrf 漏洞。

这篇文章会解释在什么场景下这构成一个安全问题以及你如何发现这种问题。

### setting up

当你可以使一个服务器对另一个服务器发送一个请求时候，就可能存在 ssrf 漏洞。在这篇文章中，最好在本地建立一个存在 ssrf 漏洞的应用来体验一下找个
漏洞。我们来假设有一台服务器运行以下 ruby 代码

```ruby
require 'sinatra'
require 'open-uri'
get '/' do
  format 'RESPONSE: %s', open(params[:url]).read
end

```
安装 gem，_gem_ _install_ _sinatra_ ，在本地运行这段代码 _ruby_ _server.rb_ 。此时在服务器就运行在  http://localhost:4567 了。不要在出了本地回环的接口运行这段代码，否则会导致命令执行漏洞。

当有人请求 http://localhost:4567/?url=https://www.baidu.com 时候，open()  函数会去访问百度页面，并且把响应体返回给客户端。 


![img](http://p04hnmyh8.bkt.clouddn.com/WechatIMG72.jpeg)

但是，从英特网中访问一个 url 并返回结果并不令人感兴趣也不属于安全漏洞，因为所有人都可以访问这些资源。现在我们花点时间考虑一下 LANs ，大量的英特网都隐藏在路由器和防火墙的后面。路由器使用 NAT 模式在内部 IP 子网和外网之间转发数据。

要解释清楚这种影响，考虑一下，我们刚才用 ruby 代码运行的 web-server 服务器和另外一个 admin-panel 服务器在同一个局域网内。admin-panel 服务器开放 80 端口并且没有认证机制。路由器可以将所有的内部流量转发到外部，在内部服务器之间没有任何防火墙。admin-panel 不能被从外网访问，web-server 可以通过于域名 web-server.com 在外网被访问到。


我们可以先访问 web-server，再通过 web-server 访问 admin-panel，admin-panel 就可以返回 http response 给外界。可以把它类比为代理，但是更像滥用外部请求到内部请求的代理。 

### Testing
现在你基本了解了 ssrf 漏洞，现在研究一下如何测试这个漏洞。在我发现的所有 ssrf 漏洞中，我认为最有用的一点是有一台可以回连的服务器。我喜欢 DigitalOcean，但是你也可以用一台能够从英特网转发通信量的机器。

我们在 http://web-server.com/4567 上,通过这台服务器 ping 我们的机器来调试 ssrf 问题。首先在本地服务器上用 netcat 监听请求。

```
hack-box-1 $  nc -l -n -vv -p 8080 -k 
```

这样操作会监听所有接口上8080的请球，并将网络请求展示出来。在这个例子中，我们假设 hack-box-1 的 ip 地址为1.2.3.4。现在请我们让 web-server.com ping 这台服务器。

```
hack-box-01 $ curl http://web-server.com:4567/\?url\=http://1.2.3.4:8080/
```

当你执行了这条命令，你会在 netcat 监听器里发现 http 请求

```
hack-box-1 $ nc -l -n -vv -p 8080 -k
Listening on [0.0.0.0] (family 0, port 8080)
Connection from [masked] port 8080 [tcp/*] accepted (family 2, sport 45982)
GET / HTTP/1.1
Accept-Encoding: gzip;q=1.0,deflate;q=0.6,identity;q=0.3
Accept: */*
User-Agent: Ruby
Host: 1.2.3.4:8080
```
这表明了 http 请求正在被发往你在 url 参数中传递的 ip 地址。过去我几年我见过的几乎所有 http 库都会遵循 http 请求。如果你的服务器，也就是这篇文章中的 netcat 监听器，会以下面的方式相应 http 请求，web-server 会对 http://10.0.0.2 发起请求。
```
HTTP/1.1 302 Found
Location: http://10.0.0.2/
Content-Length: 0
``` 
这个为什么重要呢？我见过一些公司的通过限制访问内网服务的机器来修复这个问题。但是，这种限制多 http 转发没有什么作用，考虑一下你的服务器上运行以下代码
```
require 'sinatra'
require 'open-uri'

get '/' do
  url = URI.parse params[:url]

  halt 403 if url.host =~ /\A10\.0\.0\.\d+\z/

  format 'RESPONSE: %s', open(params[:url]).read
end
```
这段代在发出请求之前解析 url 。如果传递的 url 的 ip 地址匹配了 10.0.0.[任何数字]，就会返回403。有以下几种方法可以绕过。
* 使用10进制 ip 表示 http://167772162 取代 http://10.0.0.1
* 添加一条 DNS A 记录，指向 10.0.0.2，并且使用 http://subdomain.yourdomain.com/
* 使用转发，下面详细说明
为了通过转发到达10.0.0.2，首先请求得去你的服务器上。之后再从那个服务器转发到达10.0.0.2。这回绕过上述代码的过滤手段，因请求早已经到达 open() 方法了。上面的代码使用的是黑名单，但是你得考虑到很多种情况所以很可能被绕过。下面的代码使用白名单，请尝试找到重定向漏洞。

```
require 'sinatra'
require 'open-uri'

get '/' do
  url = URI.parse params[:url]

  halt 403 unless url.host == 'web-server.com'

  format 'RESPONSE: %s', open(params[:url]).read
end

```
以下5种情况比较容易出现 ssrf
* Webhooks：当特定是时间发生时，发起 http 请求寻找服务。在大多数 webhooks 特性中，用户可以选择他们自己的终端和主机名。尝试向内网发起服务。
* PDF 生成器：尝试注入 <iframe>,\<img>,\<base>,\<script> 等元素或者 CSS 中的 url() 函数指向内网资源。
* 文档解析：
* 超链接：
* 文件上传：不上传文件，发送一个 url 看是否下载 url 里面的内容

### impact
因为 web-server 可以访问 admin-panel，所以攻击者可以获取内网信息并且访问内网服务。但是不是所有的 ssrf 都返回信息，有一种叫做 blind ssrf。
代码如下：

```
require 'sinatra'
require 'open-uri'

get '/' do
  open params[:url]

  'done'
end
```
这种情况只返回字符串 'done'，通常用于服务发现和端口扫描。

_暴露内网和防火墙之后的系统_

一个好的 ssrf 示例可以泄露出没有暴露在外网的系统。如果你想要发现内网服务，以下是私有 ipv4 网络地址。
* 10.0.0.0/8
* 127.0.0.1/32
* 172.16.0.0/12
* 192.168.0.0/16

技巧：为了发现哪一个网络在内部被路由，可以观察相应时间。没有经过路由的网络会迅速被路由器丢弃。内部防火墙规则则会被路由的网络增加RTT。同时，记住路由器跟交换机通常会开启 http 和 ssh 服务，可以尝试在.1和.254 上探测22，80，443，8080，8443端口。

_服务发现和端口扫描_

### piovts
正如你所想的那样，不是所有 ssrf 使用 http 协议。有时候使用了不同的协议或者在转发时候切换成了别的协议。可以使用gopher://protocal协议 




原文：

[https://www.hackerone.com/blog-How-To-Server-Side-Request-Forgery-SSRF](another-page).
