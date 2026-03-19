LOG_TIME=$(date "+%Y%m%d_%H%M%S")
LOG_FILE="./logs/$LOG_TIME.log"


nohup ./monaiauth > "$LOG_FILE" 2>&1 &
echo "✅ monaiauth 已启动，日志写入：$LOG_FILE"
