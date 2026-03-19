#!/bin/bash

# 1. 获取进程名参数
PROCESS_NAME="monaiauth"

# 3. 查找进程 PID（排除 grep 自己）
PID=$(ps aux | grep "$PROCESS_NAME" | grep -v grep | awk '{print $2}')

# 4. 检查是否找到 PID
if [ -z "$PID" ]; then
  echo "⚠️ 没有找到进程：$PROCESS_NAME"
  exit 0
fi

# 5. 杀掉进程
echo "🔍 发现进程 PID: $PID"
kill $PID
echo "✅ 已结束进程 $PROCESS_NAME (PID=$PID)"
