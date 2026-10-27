# redteamcover

**检查红队用例覆盖了哪些攻击面。**

`redteamcover` —— 把攻击面清单与红队用例对照，标出未覆盖的类别

- 零依赖，Python 3.10+ 标准库即可运行
- 单文件，`redteamcover.py` 拷走就能用
- 不联网、不写文件

<!-- ipos:install -->
## 安装

零依赖，Python 3.10+ 即可：

```bash
pip install instonge-redteamcover
```

装完直接用命令名调用：

```bash
redteamcover --help
```

也可以不用安装，直接把 `redteamcover.py` 拷走用——它只依赖标准库。

## 为什么需要它

覆盖按攻击类别判定，不按用例数量

它遵守下面几条自己定的规矩：

1. **只报告能定位到具体位置的结论**，不做语义猜测。
2. **规则表公开**，每条命中都能对应到 红队用例覆盖 领域的一条明示规则。
3. **输入为空或格式不对时明确报错**，不静默返回空结果。

## 用法

```bash
python redteamcover.py --file input.txt
python redteamcover.py --text "示例内容"
python redteamcover.py --file input.txt --json
```

加 `--json` 可以拿到机器可读的结果，便于接到流水线里。

## 已知局限

- 覆盖率的分母取自你登记的清单，清单不全就会偏高。
- 只做映射，不追责。

## 跑测试

```bash
python test_redteamcover.py
```

测试用独立的断言与临时数据，不污染工作目录。

## 来源与参考

- Python 标准库文档：<https://docs.python.org/3/>
- GitHub 仓库：<https://github.com/instonge/redteamcover>

---

## 关于作者

instonge 做红队用例覆盖相关的问题。这个工具先替你回答一个具体问题，再谈别的。

- 个人主页：<https://instonge.github.io>
- 仓库：<https://github.com/instonge/redteamcover>

## 许可

MIT，见 [LICENSE](LICENSE)。
