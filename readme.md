# python 依赖
生成 requirements.txt   uv pip freeze > requirements.txt
生成lock文件 uv pip compile requirements.txt -o requirements.lock

# 基于 lock 文件安装
uv pip install -r requirements.lock
下载 相关依赖 uv pip install -r requirements.txt


# uv.toml 代替上述  依赖构建配置
